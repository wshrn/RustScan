//! Provides a means to hold configuration options specifically for port scanning.
mod range_iterator;
use crate::input::{PortRange, ScanOrder};
use rand::rng;
use rand::seq::SliceRandom;
use range_iterator::RangeIterator;
use std::collections::BTreeSet;

/// Represents options of port scanning.
///
/// Right now all these options involve ranges, but in the future
/// it will also contain custom lists of ports.
#[derive(Debug)]
pub enum PortStrategy {
    Manual(Vec<u16>),
    Serial(SerialRange),
    Random(RandomRange),
}

impl PortStrategy {
    pub fn pick(range: &Option<PortRange>, ports: Option<Vec<u16>>, order: ScanOrder) -> Self {
        match order {
            ScanOrder::Serial if ports.is_none() => {
                let range = range.as_ref().unwrap();
                PortStrategy::Serial(SerialRange {
                    start: range.start,
                    end: range.end,
                })
            }
            ScanOrder::Random if ports.is_none() => {
                let range = range.as_ref().unwrap();
                PortStrategy::Random(RandomRange {
                    start: range.start,
                    end: range.end,
                })
            }
            ScanOrder::Serial => PortStrategy::Manual(ports.unwrap()),
            ScanOrder::Random => {
                let mut rng = rng();
                let mut ports = ports.unwrap();
                ports.shuffle(&mut rng);
                PortStrategy::Manual(ports)
            }
            ScanOrder::HighFrequency => {
                let high_frequency_ports = build_high_frequency_ports();
                match ports {
                    Some(ports) => {
                        let port_set: BTreeSet<u16> = ports.iter().copied().collect();
                        let mut prioritized: Vec<u16> = high_frequency_ports
                            .into_iter()
                            .filter(|port| port_set.contains(port))
                            .collect();
                        let prioritized_set: BTreeSet<u16> = prioritized.iter().copied().collect();
                        for port in ports {
                            if !prioritized_set.contains(&port) {
                                prioritized.push(port);
                            }
                        }
                        PortStrategy::Manual(prioritized)
                    }
                    None => {
                        let range = range.as_ref().unwrap();
                        let mut prioritized: Vec<u16> = high_frequency_ports
                            .into_iter()
                            .filter(|port| *port >= range.start && *port <= range.end)
                            .collect();
                        let mut seen: BTreeSet<u16> = prioritized.iter().copied().collect();
                        for port in range.start..=range.end {
                            if seen.insert(port) {
                                prioritized.push(port);
                            }
                        }
                        PortStrategy::Manual(prioritized)
                    }
                }
            }
        }
    }

    pub fn order(&self) -> Vec<u16> {
        match self {
            PortStrategy::Manual(ports) => ports.clone(),
            PortStrategy::Serial(range) => range.generate(),
            PortStrategy::Random(range) => range.generate(),
        }
    }
}

fn build_high_frequency_ports() -> Vec<u16> {
    const SERVICE_PORTS: &[u16] = &[
        21, 22, 23, 25, 110, 135, 139, 143, 162, 389, 445, 465, 502, 587, 636, 873, 993, 995, 1433,
        1521, 2222, 3306, 3389, 5020, 5432, 5672, 5671, 6379, 8161, 8443, 9000, 9092, 9093, 9200,
        10051, 11211, 15672, 15671, 27017, 61616, 61613,
    ];
    const DB_PORTS: &[u16] = &[
        1433, 1521, 3306, 5432, 5672, 6379, 7687, 9042, 9093, 9200, 11211, 27017, 61616,
    ];
    #[allow(clippy::too_many_lines)]
    const WEB_PORTS: &[u16] = &[
        80, 81, 82, 83, 84, 85, 86, 87, 88, 89, 90, 91, 92, 98, 99, 443, 800, 801, 808, 880, 888,
        889, 1000, 1010, 1080, 1081, 1082, 1099, 1118, 1888, 2008, 2020, 2100, 2375, 2379, 3000,
        3008, 3128, 3505, 5555, 6080, 6648, 6868, 7000, 7001, 7002, 7003, 7004, 7005, 7007, 7008,
        7070, 7071, 7074, 7078, 7080, 7088, 7200, 7680, 7687, 7688, 7777, 7890, 8000, 8001, 8002,
        8003, 8004, 8005, 8006, 8008, 8009, 8010, 8011, 8012, 8016, 8018, 8020, 8028, 8030, 8038,
        8042, 8044, 8046, 8048, 8053, 8060, 8069, 8070, 8080, 8081, 8082, 8083, 8084, 8085, 8086,
        8087, 8088, 8089, 8090, 8091, 8092, 8093, 8094, 8095, 8096, 8097, 8098, 8099, 8100, 8101,
        8108, 8118, 8161, 8172, 8180, 8181, 8200, 8222, 8244, 8258, 8280, 8288, 8300, 8360, 8443,
        8448, 8484, 8800, 8834, 8838, 8848, 8858, 8868, 8879, 8880, 8881, 8888, 8899, 8983, 8989,
        9000, 9001, 9002, 9008, 9010, 9043, 9060, 9080, 9081, 9082, 9083, 9084, 9085, 9086, 9087,
        9088, 9089, 9090, 9091, 9092, 9093, 9094, 9095, 9096, 9097, 9098, 9099, 9100, 9200, 9443,
        9448, 9800, 9981, 9986, 9988, 9998, 9999, 10000, 10001, 10002, 10004, 10008, 10010, 10051,
        10250, 12018, 12443, 14000, 15672, 15671, 16080, 18000, 18001, 18002, 18004, 18008, 18080,
        18082, 18088, 18090, 18098, 19001, 20000, 20720, 20880, 21000, 21501, 21502, 28018,
    ];

    let mut set = BTreeSet::new();
    for port in SERVICE_PORTS
        .iter()
        .chain(DB_PORTS.iter())
        .chain(WEB_PORTS.iter())
    {
        set.insert(*port);
    }

    set.into_iter().collect()
}

/// Trait associated with a port strategy. Each PortStrategy must be able
/// to generate an order for future port scanning.
trait RangeOrder {
    fn generate(&self) -> Vec<u16>;
}

/// As the name implies SerialRange will always generate a vector in
/// ascending order.
#[derive(Debug)]
pub struct SerialRange {
    start: u16,
    end: u16,
}

impl RangeOrder for SerialRange {
    fn generate(&self) -> Vec<u16> {
        (self.start..=self.end).collect()
    }
}

/// As the name implies RandomRange will always generate a vector with
/// a random order. This vector is built following the LCG algorithm.
#[derive(Debug)]
pub struct RandomRange {
    start: u16,
    end: u16,
}

impl RangeOrder for RandomRange {
    // Right now using RangeIterator and generating a range + shuffling the
    // vector is pretty much the same. The advantages of it will come once
    // we have to generate different ranges for different IPs without storing
    // actual vectors.
    //
    // Another benefit of RangeIterator is that it always generate a range with
    // a certain distance between the items in the Array. The chances of having
    // port numbers close to each other are pretty slim due to the way the
    // algorithm works.
    fn generate(&self) -> Vec<u16> {
        RangeIterator::new(self.start.into(), self.end.into()).collect()
    }
}

#[cfg(test)]
mod tests {
    use super::PortStrategy;
    use crate::input::{PortRange, ScanOrder};

    #[test]
    fn serial_strategy_with_range() {
        let range = PortRange { start: 1, end: 100 };
        let strategy = PortStrategy::pick(&Some(range), None, ScanOrder::Serial);
        let result = strategy.order();
        let expected_range = (1..=100).collect::<Vec<u16>>();
        assert_eq!(expected_range, result);
    }
    #[test]
    fn random_strategy_with_range() {
        let range = PortRange { start: 1, end: 100 };
        let strategy = PortStrategy::pick(&Some(range), None, ScanOrder::Random);
        let mut result = strategy.order();
        let expected_range = (1..=100).collect::<Vec<u16>>();
        assert_ne!(expected_range, result);

        result.sort_unstable();
        assert_eq!(expected_range, result);
    }

    #[test]
    fn serial_strategy_with_ports() {
        let strategy = PortStrategy::pick(&None, Some(vec![80, 443]), ScanOrder::Serial);
        let result = strategy.order();
        assert_eq!(vec![80, 443], result);
    }

    #[test]
    fn random_strategy_with_ports() {
        let strategy = PortStrategy::pick(&None, Some((1..10).collect()), ScanOrder::Random);
        let mut result = strategy.order();
        let expected_range = (1..10).collect::<Vec<u16>>();
        assert_ne!(expected_range, result);

        result.sort_unstable();
        assert_eq!(expected_range, result);
    }

    #[test]
    fn high_frequency_strategy_with_range_prioritises_ports() {
        let range = PortRange { start: 80, end: 85 };
        let strategy = PortStrategy::pick(&Some(range), None, ScanOrder::HighFrequency);
        let result = strategy.order();
        assert_eq!(vec![80, 81, 82, 83, 84, 85], result);
    }

    #[test]
    fn high_frequency_strategy_with_ports_prioritises_known_ports() {
        let strategy =
            PortStrategy::pick(&None, Some(vec![22, 23, 24, 25]), ScanOrder::HighFrequency);
        let result = strategy.order();
        assert_eq!(vec![22, 23, 25, 24], result);
    }
}
