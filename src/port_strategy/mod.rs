//! Provides a means to hold configuration options specifically for port scanning.
mod range_iterator;
use crate::input::{PortRange, PortSelection, ScanOrder};
use rand::rng;
use rand::seq::SliceRandom;
use range_iterator::RangeIterator;
use std::collections::HashSet;

const SERVICE_PORTS: &[u16] = &[
    21, 22, 23, 25, 110, 135, 139, 143, 162, 389, 445, 465, 502, 587, 636, 873, 993, 995, 1433,
    1521, 2222, 3306, 3389, 5020, 5432, 5672, 5671, 6379, 8161, 8443, 9000, 9092, 9093, 9200,
    10051, 11211, 15672, 15671, 27017, 61616, 61613,
];

const DB_PORTS: &[u16] = &[
    1433, 1521, 3306, 5432, 5672, 6379, 7687, 9042, 9093, 9200, 11211, 27017, 61616,
];

const WEB_PORTS: &[u16] = &[
    80, 81, 82, 83, 84, 85, 86, 87, 88, 89, 90, 91, 92, 98, 99, 443, 800, 801, 808, 880, 888, 889,
    1000, 1010, 1080, 1081, 1082, 1099, 1118, 1888, 2008, 2020, 2100, 2375, 2379, 3000, 3008, 3128,
    3505, 5555, 6080, 6648, 6868, 7000, 7001, 7002, 7003, 7004, 7005, 7007, 7008, 7070, 7071, 7074,
    7078, 7080, 7088, 7200, 7680, 7687, 7688, 7777, 7890, 8000, 8001, 8002, 8003, 8004, 8005, 8006,
    8008, 8009, 8010, 8011, 8012, 8016, 8018, 8020, 8028, 8030, 8038, 8042, 8044, 8046, 8048, 8053,
    8060, 8069, 8070, 8080, 8081, 8082, 8083, 8084, 8085, 8086, 8087, 8088, 8089, 8090, 8091, 8092,
    8093, 8094, 8095, 8096, 8097, 8098, 8099, 8100, 8101, 8108, 8118, 8161, 8172, 8180, 8181, 8200,
    8222, 8244, 8258, 8280, 8288, 8300, 8360, 8443, 8448, 8484, 8800, 8834, 8838, 8848, 8858, 8868,
    8879, 8880, 8881, 8888, 8899, 8983, 8989, 9000, 9001, 9002, 9008, 9010, 9043, 9060, 9080, 9081,
    9082, 9083, 9084, 9085, 9086, 9087, 9088, 9089, 9090, 9091, 9092, 9093, 9094, 9095, 9096, 9097,
    9098, 9099, 9100, 9200, 9443, 9448, 9800, 9981, 9986, 9988, 9998, 9999, 10000, 10001, 10002,
    10004, 10008, 10010, 10051, 10250, 12018, 12443, 14000, 15672, 15671, 16080, 18000, 18001,
    18002, 18004, 18008, 18080, 18082, 18088, 18090, 18098, 19001, 20000, 20720, 20880, 21000,
    21501, 21502, 28018,
];

/// 额外的高频端口，基于 Nmap 官方 `nmap-services` 文件统计的前 1000 个 TCP 端口。
#[rustfmt::skip]
const ADDITIONAL_HIGH_FREQUENCY_PORTS: &[u16] = &[
    80, 23, 443, 21, 22, 25, 3389, 110, 445, 139, 143, 53, 135, 3306, 8080, 1723,
    111, 995, 993, 5900, 1025, 587, 8888, 199, 1720, 465, 548, 113, 81, 6001, 10000, 514,
    5060, 179, 1026, 2000, 8443, 8000, 32768, 554, 26, 1433, 49152, 2001, 515, 8008, 49154, 1027,
    5666, 646, 5000, 5631, 631, 49153, 8081, 2049, 88, 79, 5800, 106, 2121, 1110, 49155, 6000,
    513, 990, 5357, 427, 49156, 543, 544, 5101, 144, 7, 389, 8009, 3128, 444, 9999, 5009,
    7070, 5190, 3000, 5432, 1900, 3986, 13, 1029, 9, 5051, 6646, 49157, 1028, 873, 1755, 2717,
    4899, 9100, 119, 37, 1000, 3001, 5001, 82, 10010, 1030, 9090, 2107, 1024, 2103, 6004, 1801,
    5050, 19, 8031, 1041, 255, 1048, 1049, 1053, 1054, 1056, 1064, 1065, 2967, 3703, 17, 808,
    3689, 1031, 1044, 1071, 5901, 100, 9102, 1039, 2869, 4001, 5120, 8010, 9000, 2105, 636, 1038,
    2601, 1, 7000, 1066, 1069, 625, 311, 280, 254, 4000, 1761, 5003, 2002, 1998, 2005, 1032,
    1050, 6112, 3690, 1521, 2161, 1080, 6002, 2401, 902, 4045, 787, 7937, 1058, 2383, 32771, 1033,
    1040, 1059, 50000, 5555, 10001, 1494, 3, 593, 2301, 3268, 7938, 1022, 1234, 1035, 1036, 1037,
    1074, 8002, 9001, 464, 497, 1935, 2003, 6666, 6543, 24, 1352, 3269, 1111, 407, 500, 20,
    2006, 1034, 1218, 3260, 15000, 4444, 264, 33, 2004, 1042, 42510, 999, 3052, 1023, 222, 1068,
    888, 7100, 563, 1717, 992, 2008, 32770, 7001, 32772, 2007, 8082, 5550, 512, 1043, 2009, 5801,
    1700, 2701, 7019, 50001, 4662, 2065, 42, 2010, 161, 2602, 3333, 9535, 5100, 2604, 4002, 5002,
    1047, 1051, 1052, 1055, 1060, 1062, 1311, 2702, 3283, 4443, 5225, 5226, 6059, 6789, 8089, 8192,
    8193, 8194, 8651, 8652, 8701, 9415, 9593, 9594, 9595, 16992, 16993, 20828, 23502, 32769, 33354, 35500,
    52869, 55555, 55600, 64623, 64680, 65000, 65389, 1067, 13782, 366, 5902, 9050, 85, 1002, 5500, 1863,
    1864, 5431, 8085, 10243, 45100, 49999, 51103, 49, 90, 6667, 1503, 6881, 27000, 340, 1500, 8021,
    2222, 5566, 8088, 8899, 9071, 1501, 5102, 6005, 9101, 9876, 32773, 32774, 163, 5679, 146, 648,
    1666, 901, 83, 3476, 5004, 5214, 8001, 8083, 8084, 9207, 14238, 30, 912, 12345, 2030, 2605,
    6, 541, 4, 1248, 3005, 8007, 306, 880, 2500, 1086, 1088, 1097, 2525, 4242, 8291, 9009,
    52822, 900, 6101, 2809, 7200, 211, 800, 987, 1083, 12000, 32775, 705, 711, 20005, 6969, 13783,
    1045, 1046, 1057, 1061, 1063, 1070, 1072, 1073, 1075, 1077, 1078, 1079, 1081, 1082, 1085, 1093,
    1094, 1096, 1098, 1099, 1100, 1104, 1106, 1107, 1108, 1148, 1169, 1272, 1310, 1687, 1718, 1783,
    1840, 1947, 2100, 2119, 2135, 2144, 2160, 2190, 2260, 2381, 2399, 2492, 2607, 2718, 2811, 2875,
    3017, 3031, 3071, 3211, 3300, 3301, 3323, 3325, 3351, 3367, 3404, 3551, 3580, 3659, 3766, 3784,
    3801, 3827, 3998, 4003, 4126, 4129, 4449, 5030, 5222, 5269, 5414, 5633, 5718, 5810, 5825, 5877,
    5910, 5911, 5925, 5959, 5960, 5961, 5962, 5985, 5986, 5987, 5988, 5989, 6123, 6129, 6156, 6389,
    6580, 6788, 6901, 7106, 7625, 7627, 7741, 7777, 7778, 7911, 8086, 8087, 8181, 8222, 8333, 8400,
    8402, 8600, 8649, 8873, 8994, 9002, 9010, 9011, 9080, 9220, 9290, 9485, 9500, 9502, 9503, 9618,
    9900, 9968, 10002, 10012, 10024, 10025, 10566, 10616, 10617, 10621, 10626, 10628, 10629, 11110, 11967, 13456,
    14000, 14442, 15002, 15003, 15660, 16001, 16016, 16018, 17988, 19101, 19801, 19842, 20000, 20031, 20221, 20222,
    21571, 22939, 24800, 25734, 27715, 28201, 30000, 30718, 31038, 32781, 32782, 33899, 34571, 34572, 34573, 40193,
    48080, 49158, 49159, 49160, 50003, 50006, 50800, 57294, 58080, 60020, 63331, 65129, 89, 691, 212, 1001,
    1999, 2020, 32776, 2998, 6003, 7002, 50002, 32, 898, 2033, 3372, 5510, 99, 425, 749, 5903,
    43, 458, 5405, 6106, 6502, 7007, 13722, 1087, 1089, 1124, 1152, 1183, 1186, 1247, 1296, 1334,
    1580, 1782, 2126, 2179, 2191, 2251, 2522, 3011, 3030, 3077, 3261, 3369, 3370, 3371, 3493, 3546,
    3737, 3828, 3851, 3871, 3880, 3918, 3995, 4006, 4111, 4446, 5054, 5200, 5280, 5298, 5822, 5859,
    5904, 5915, 5922, 5963, 7103, 7402, 7435, 7443, 7512, 8011, 8090, 8100, 8180, 8254, 8500, 8654,
    9091, 9110, 9666, 9877, 9943, 9944, 9998, 10004, 10778, 15742, 16012, 18988, 19283, 19315, 19780, 24444,
    27352, 27353, 27355, 32784, 49163, 49165, 49175, 50389, 50636, 51493, 55055, 56738, 61532, 61900, 62078, 1021,
    9040, 32777, 32779, 616, 666, 700, 2021, 32778, 84, 545, 1112, 1524, 2040, 4321, 5802, 38292,
    49400, 1084, 1600, 2048, 2111, 3006, 32780, 2638, 6547, 6699, 9111, 16080, 555, 667, 720, 801,
    1443, 1533, 2034, 2106, 5560, 6007, 1090, 1091, 1114, 1117, 1119, 1122, 1131, 1138, 1151, 1175,
    1199, 1201, 1271, 1862, 2323, 2393, 2394, 2608, 2725, 2909, 3003, 3168, 3221, 3322, 3324, 3390,
    3517, 3527, 3800, 3809, 3814, 3826, 3869, 3878, 3889, 3905, 3914, 3920, 3945, 3971, 4004, 4005,
    4279, 4445, 4550, 4567, 4848, 4900, 5033, 5061, 5080, 5087, 5221, 5440, 5544, 5678, 5730, 5811,
    5815, 5850, 5862, 5906, 5907, 5950, 5952, 6025, 6100, 6510, 6565, 6566, 6567, 6689, 6692, 6779,
    6792, 6839, 7025, 7496, 7676, 7800, 7920, 7921, 7999, 8022, 8042, 8045, 8093, 8099, 8200, 8290,
    8292, 8300, 8383, 8800, 9003, 9081, 9099, 9200, 9418, 9575, 9878, 9898, 9917, 10003, 10009, 10180,
    10215, 11111, 12174, 12265, 14441, 15004, 16000, 16113, 17877, 18040, 18101, 19350, 25735, 26214, 27356, 30951,
    32783, 32785, 40911, 41511, 44176, 44501, 49161, 49167, 49176, 50300, 50500, 52673, 52848, 54045, 54328, 55056,
    56737, 57797, 60443, 70, 417, 617, 714, 722, 777, 981, 1009, 2022, 4224, 4998, 6346, 301,
    524, 668, 765, 1076, 2041, 5999, 10082, 259, 416, 1007, 1417, 1434, 1984, 2038, 2068, 4343,
    6009, 7004, 44443, 109, 687, 726, 911, 1010, 1461, 2035, 2046, 4125, 6006, 7201, 9103, 125,
    481, 683, 903, 1011, 1455, 2013, 2043, 2047, 6668, 6669, 256, 406, 783, 843, 2042, 2045,
    5998, 9929, 31337, 44442, 1092, 1095, 1102, 1105, 1113, 1121, 1123, 1126, 1130, 1132, 1137, 1141,
    1145, 1147, 1149, 1154, 1163, 1164, 1165, 1166, 1174, 1185, 1187, 1192, 1198, 1213, 1216, 1217,
    1233, 1236, 1244, 1259, 1277, 1287, 1300, 1301, 1309, 1322, 1328, 1556, 1583, 1594, 1641, 1658,
    1688, 1719, 1721, 1805, 1812, 1839, 1875, 1914, 1971, 1972, 1974, 2099, 2170, 2196, 2200, 2288,
    2366, 2382, 2557, 2710, 2800, 2910, 2920, 2968,
];
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
    pub fn pick(selection: &PortSelection, order: ScanOrder) -> Self {
        match (order, selection) {
            (ScanOrder::Serial, PortSelection::Range(range)) => PortStrategy::Serial(SerialRange {
                start: range.start,
                end: range.end,
            }),
            (ScanOrder::Serial, PortSelection::List(ports)) => PortStrategy::Manual(ports.clone()),
            (ScanOrder::Random, PortSelection::Range(range)) => PortStrategy::Random(RandomRange {
                start: range.start,
                end: range.end,
            }),
            (ScanOrder::Random, PortSelection::List(ports)) => {
                let mut rng = rng();
                let mut ports = ports.clone();
                ports.shuffle(&mut rng);
                PortStrategy::Manual(ports)
            }
            (ScanOrder::HighFrequency, PortSelection::Range(range)) => {
                PortStrategy::Manual(build_high_frequency_range(range))
            }
            (ScanOrder::HighFrequency, PortSelection::List(ports)) => {
                PortStrategy::Manual(build_high_frequency_manual(ports))
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

fn combined_high_frequency_ports() -> impl Iterator<Item = &'static u16> {
    SERVICE_PORTS
        .iter()
        .chain(DB_PORTS.iter())
        .chain(WEB_PORTS.iter())
        .chain(ADDITIONAL_HIGH_FREQUENCY_PORTS.iter())
}

fn build_high_frequency_range(range: &PortRange) -> Vec<u16> {
    let mut seen = HashSet::new();
    let mut ports = Vec::new();

    for &port in combined_high_frequency_ports() {
        if (range.start..=range.end).contains(&port) && seen.insert(port) {
            ports.push(port);
        }
    }

    for port in range.start..=range.end {
        if seen.insert(port) {
            ports.push(port);
        }
    }

    ports
}

fn build_high_frequency_manual(manual_ports: &[u16]) -> Vec<u16> {
    let mut seen = HashSet::new();
    let mut ordered_ports = Vec::new();
    let mut manual_sorted = manual_ports.to_vec();
    manual_sorted.sort_unstable();

    let manual_set: HashSet<u16> = manual_sorted.iter().copied().collect();

    for &port in combined_high_frequency_ports() {
        if manual_set.contains(&port) && seen.insert(port) {
            ordered_ports.push(port);
        }
    }

    for port in manual_sorted {
        if seen.insert(port) {
            ordered_ports.push(port);
        }
    }

    ordered_ports
}

#[cfg(test)]
mod tests {
    use super::PortStrategy;
    use crate::input::{PortRange, PortSelection, ScanOrder};

    #[test]
    fn serial_strategy_with_range() {
        let range = PortRange { start: 1, end: 100 };
        let strategy = PortStrategy::pick(&PortSelection::Range(range), ScanOrder::Serial);
        let result = strategy.order();
        let expected_range = (1..=100).collect::<Vec<u16>>();
        assert_eq!(expected_range, result);
    }
    #[test]
    fn random_strategy_with_range() {
        let range = PortRange { start: 1, end: 100 };
        let strategy = PortStrategy::pick(&PortSelection::Range(range), ScanOrder::Random);
        let mut result = strategy.order();
        let expected_range = (1..=100).collect::<Vec<u16>>();
        assert_ne!(expected_range, result);

        result.sort_unstable();
        assert_eq!(expected_range, result);
    }

    #[test]
    fn serial_strategy_with_ports() {
        let strategy = PortStrategy::pick(&PortSelection::List(vec![80, 443]), ScanOrder::Serial);
        let result = strategy.order();
        assert_eq!(vec![80, 443], result);
    }

    #[test]
    fn random_strategy_with_ports() {
        let strategy =
            PortStrategy::pick(&PortSelection::List((1..10).collect()), ScanOrder::Random);
        let mut result = strategy.order();
        let expected_range = (1..10).collect::<Vec<u16>>();
        assert_ne!(expected_range, result);

        result.sort_unstable();
        assert_eq!(expected_range, result);
    }

    #[test]
    fn high_frequency_with_range_prioritises_known_ports() {
        let range = PortRange { start: 80, end: 85 };
        let strategy = PortStrategy::pick(&PortSelection::Range(range), ScanOrder::HighFrequency);
        let result = strategy.order();
        assert_eq!(result[0], 80);
        assert_eq!(result, vec![80, 81, 82, 83, 84, 85]);
    }

    #[test]
    fn high_frequency_with_manual_ports_prioritises_known_ports() {
        let strategy = PortStrategy::pick(
            &PortSelection::List(vec![8080, 22, 9999, 9000]),
            ScanOrder::HighFrequency,
        );
        let result = strategy.order();
        assert_eq!(&result[..2], &[22, 9000]);
        assert_eq!(result, vec![22, 9000, 8080, 9999]);
    }
}
