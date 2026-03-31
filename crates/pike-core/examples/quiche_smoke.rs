fn main() {
    let mut config = quiche::Config::new(quiche::PROTOCOL_VERSION).unwrap();
    config.set_application_protos(&[b"pike/1"]).unwrap();
    config.set_cc_algorithm(quiche::CongestionControlAlgorithm::Bbr2Gcongestion);
    config.enable_early_data();

    println!(
        "✓ quiche {} initialized successfully",
        quiche::PROTOCOL_VERSION
    );
    println!("✓ BBR2 congestion control set");
    println!("✓ 0-RTT early data enabled");
    println!("✓ Custom protocol 'pike/1' registered");
    println!("\nSmoke test PASSED — quiche is ready for Pike development");
}
