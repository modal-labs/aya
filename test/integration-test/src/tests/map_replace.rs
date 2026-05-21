use std::os::fd::AsFd as _;

use aya::{
    Ebpf, EbpfError, EbpfLoader,
    maps::{HashMap, Map, MapData, MapError, MapType},
    programs::{ProgramType, SocketFilter},
    sys::{is_map_supported, is_program_supported},
};
use aya_obj::generated::bpf_map_type::BPF_MAP_TYPE_HASH;

#[test_log::test]
fn map_replace_shares_state() {
    if !is_program_supported(ProgramType::SocketFilter).unwrap() {
        eprintln!("skipping test - socket_filter program not supported");
        return;
    } else if !is_map_supported(MapType::Hash).unwrap() {
        eprintln!("skipping test - hash map not supported");
        return;
    } else if !is_map_supported(MapType::Array).unwrap() {
        eprintln!("skipping test - array map not supported");
        return;
    }

    // First load: this creates the kernel map for BAR. We never pin it; the
    // map's lifetime is tied to the BPF program (held by `first`) plus any
    // user-space FDs we keep open.
    let mut first: Ebpf = Ebpf::load(crate::MAP_TEST).unwrap();
    let prog: &mut SocketFilter = first.program_mut("simple_prog").unwrap().try_into().unwrap();
    prog.load().unwrap();

    // Dup the kernel FD of BAR into a fresh MapData and hand it to the second
    // loader. No filesystem pin involved — the kernel will refcount the map by
    // FD and clean it up once `first`, our dup, and the second program all go
    // away.
    let bar_borrowed = match first.map("BAR").unwrap() {
        Map::HashMap(md) => md,
        other => panic!("BAR is not a HashMap: {other:?}"),
    };
    let reused_fd = bar_borrowed.fd().as_fd().try_clone_to_owned().unwrap();
    let reused = MapData::from_fd(reused_fd).unwrap();

    // Seed a value through the first program's BAR map.
    {
        let mut bar_first: HashMap<_, u32, u8> =
            HashMap::try_from(first.map_mut("BAR").unwrap()).unwrap();
        bar_first.insert(7, 42, 0).unwrap();
    }

    let mut second = EbpfLoader::new()
        .map_replace("BAR", reused)
        .load(crate::MAP_TEST)
        .unwrap();
    let prog2: &mut SocketFilter = second
        .program_mut("simple_prog")
        .unwrap()
        .try_into()
        .unwrap();
    prog2.load().unwrap();

    // Replacement should make `second`'s BAR alias the same kernel map.
    let bar_second: HashMap<_, u32, u8> = HashMap::try_from(second.map("BAR").unwrap()).unwrap();
    assert_eq!(bar_second.get(&7, 0).unwrap(), 42);

    // Writes through `second` should be visible via `first`.
    {
        let mut bar_second_mut: HashMap<_, u32, u8> =
            HashMap::try_from(second.map_mut("BAR").unwrap()).unwrap();
        bar_second_mut.insert(9, 99, 0).unwrap();
    }
    let bar_first_ro: HashMap<_, u32, u8> = HashMap::try_from(first.map("BAR").unwrap()).unwrap();
    assert_eq!(bar_first_ro.get(&9, 0).unwrap(), 99);
}

#[test_log::test]
fn map_replace_rejects_incompatible() {
    if !is_map_supported(MapType::Hash).unwrap() {
        eprintln!("skipping test - hash map not supported");
        return;
    }

    // BAR is declared as HashMap<u32, u8>; build a HASH map with value_size=8
    // so the compat check rejects it before reaching the verifier.
    let wrong_obj = aya_obj::Map::Legacy(aya_obj::maps::LegacyMap {
        def: aya_obj::maps::bpf_map_def {
            map_type: BPF_MAP_TYPE_HASH as u32,
            key_size: size_of::<u32>() as u32,
            value_size: size_of::<u64>() as u32,
            max_entries: 8,
            map_flags: 0,
            id: 0,
            pinning: aya_obj::maps::PinningType::None,
        },
        section_index: 0,
        section_kind: aya_obj::EbpfSectionKind::Undefined,
        symbol_index: None,
        data: Vec::new(),
    });
    let wrong = MapData::create(wrong_obj, "wrong", None).unwrap();

    let err = EbpfLoader::new()
        .map_replace("BAR", wrong)
        .load(crate::MAP_TEST)
        .unwrap_err();
    assert!(
        matches!(
            err,
            EbpfError::MapError(MapError::IncompatibleReusedMap { .. })
        ),
        "expected IncompatibleReusedMap, got: {err:?}"
    );
}
