//! Provides a means to hold configuration options specifically for port scanning.
mod range_iterator;
use crate::input::{PortRange, PortSelection, ScanOrder};
use rand::rng;
use rand::seq::SliceRandom;
use range_iterator::RangeIterator;
use std::collections::{BTreeSet, HashSet};

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

/// 额外的高频端口，基于 Nmap 官方 `nmap-services` 文件统计的前 2000 个 TCP 端口。
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
    2366, 2382, 2557, 2710, 2800, 2910, 2920, 2968, 65310, 61613, 60642, 60146, 60123, 59202, 59201, 59200,
    59110, 58838, 58632, 58630, 58002, 58001, 57665, 55576, 55020, 53535, 53314, 53313, 53211, 52853, 52851, 52850,
    52849, 52847, 52735, 52710, 52660, 51413, 51191, 50050, 49401, 49236, 49195, 49186, 49171, 49168, 49164, 47544,
    46996, 46200, 44709, 41523, 41064, 40811, 40000, 39659, 39376, 39136, 38188, 38185, 37839, 35513, 33554, 33453,
    32835, 32822, 32816, 32803, 32792, 32791, 31727, 30704, 30005, 29831, 29672, 28211, 27357, 26470, 26000, 23796,
    23052, 22222, 21792, 20002, 19900, 18264, 18018, 17595, 16851, 16800, 16705, 15402, 15001, 13724, 12452, 12380,
    12262, 12215, 12059, 12021, 12006, 10873, 10160, 10058, 10034, 10023, 10022, 10011, 10008, 9988, 9941, 9914,
    9815, 9673, 9643, 9621, 9600, 9501, 9444, 9443, 9409, 9198, 9197, 9191, 9098, 8996, 8987, 8889,
    8877, 8766, 8765, 8686, 8676, 8675, 8648, 8540, 8481, 8385, 8294, 8293, 8189, 8098, 8097, 8095,
    8050, 8019, 8016, 8015, 7929, 7913, 7900, 7878, 7770, 7749, 7744, 7725, 7438, 7281, 7278, 7272,
    7241, 7123, 7080, 7051, 7050, 7024, 6896, 6732, 6711, 6600, 6550, 6520, 6504, 6500, 6481, 6247,
    6203, 6068, 6060, 6051, 5981, 5968, 5940, 5938, 5918, 5914, 5909, 5905, 5899, 5869, 5868, 5823,
    5818, 5812, 5807, 5501, 5353, 5339, 5279, 5242, 5223, 5212, 5151, 5081, 5074, 5063, 5040, 4949,
    4875, 4658, 4600, 4555, 4430, 4252, 4200, 4164, 4147, 4143, 4096, 4080, 4040, 4009, 3994, 3993,
    3990, 3981, 3972, 3969, 3968, 3963, 3957, 3944, 3941, 3931, 3929, 3916, 3907, 3888, 3872, 3870,
    3863, 3859, 3853, 3852, 3849, 3848, 3846, 3824, 3820, 3808, 3792, 3731, 3700, 3697, 3684, 3514,
    3410, 3400, 3376, 3307, 3304, 3162, 3119, 3050, 3013, 3007, 10005, 6222, 5680, 4559, 2501, 2241,
    2232, 2012, 1347, 1220, 1109, 1103, 930, 913, 803, 780, 725, 710, 701, 639, 623, 502,
    18000, 9992, 8118, 5010, 2044, 1270, 1222, 1158, 953, 931, 874, 856, 540, 475, 447, 442,
    441, 419, 250, 123, 102, 86, 27, 10083, 9152, 7003, 6103, 6008, 5803, 5520, 3299, 3025,
    2628, 2433, 1550, 1212, 1013, 1008, 980, 829, 713, 709, 556, 251, 223, 210, 87, 57,
    55, 7010, 4333, 2067, 2011, 1547, 1526, 1516, 1351, 1350, 1241, 1020, 1006, 943, 904, 840,
    825, 792, 748, 732, 684, 674, 657, 610, 557, 523, 333, 220, 157, 127, 77, 6662,
    6050, 3632, 3456, 3399, 2903, 2201, 2025, 1522, 1357, 1353, 1015, 1014, 1012, 998, 996, 971,
    969, 905, 862, 846, 839, 823, 822, 795, 790, 786, 782, 778, 757, 731, 730, 729,
    660, 659, 655, 602, 600, 257, 225, 44334, 38037, 12346, 6670, 6017, 5011, 3999, 2600, 2112,
    1525, 1414, 1413, 1337, 1127, 1005, 1004, 928, 924, 922, 921, 918, 878, 864, 859, 806,
    805, 802, 758, 754, 740, 728, 715, 690, 669, 641, 621, 606, 411, 388, 252, 98,
    59, 65514, 65488, 65311, 65048, 64890, 64727, 64726, 64551, 64507, 64438, 64320, 64127, 64080, 63803, 63675,
    63423, 63156, 63105, 62866, 62674, 62570, 62519, 62312, 62188, 62080, 62042, 62006, 61942, 61851, 61827, 61734,
    61722, 61669, 61617, 61616, 61516, 61473, 61402, 61170, 61169, 61159, 60989, 60794, 60789, 60783, 60782, 60753,
    60743, 60728, 60713, 60628, 60621, 60612, 60579, 60544, 60504, 60492, 60485, 60403, 60401, 60377, 60279, 60243,
    60227, 60177, 60111, 60086, 60055, 60003, 60002, 60000, 59987, 59841, 59829, 59810, 59778, 59684, 59565, 59525,
    59510, 59509, 59504, 59499, 59340, 59239, 59191, 59160, 59149, 59122, 59107, 59087, 58991, 58970, 58908, 58721,
    58699, 58634, 58622, 58610, 58570, 58562, 58498, 58468, 58456, 58446, 58430, 58374, 58310, 58305, 58252, 58164,
    58109, 58107, 58072, 57999, 57988, 57928, 57923, 57896, 57891, 57733, 57730, 57702, 57681, 57678, 57576, 57479,
    57398, 57387, 57352, 57350, 57347, 57335, 57325, 57123, 57103, 57020, 56975, 56973, 56827, 56822, 56810, 56725,
    56723, 56681, 56668, 56591, 56535, 56507, 56293, 56259, 56055, 56016, 55948, 55910, 55907, 55901, 55781, 55773,
    55758, 55721, 55684, 55652, 55635, 55579, 55569, 55568, 55556, 55527, 55479, 55426, 55400, 55382, 55350, 55312,
    55227, 55187, 55183, 55000, 54991, 54987, 54907, 54873, 54741, 54722, 54688, 54658, 54605, 54551, 54514, 54323,
    54321, 54276, 54263, 54235, 54127, 54101, 54075, 53958, 53910, 53852, 53827, 53782, 53742, 53690, 53656, 53639,
    53633, 53491, 53469, 53460, 53370, 53361, 53319, 53240, 53212, 53189, 53178, 53085, 52948, 52893, 52675, 52665,
    52573, 52506, 52477, 52391, 52262, 52237, 52230, 52226, 52225, 52173, 52071, 52046, 52025, 52003, 52002, 52001,
    52000, 51965, 51961, 51909, 51906, 51809, 51800, 51772, 51771, 51658, 51582, 51515, 51488, 51485, 51484, 51460,
    51423, 51366, 51351, 51343, 51300, 51240, 51235, 51234, 51233, 51139, 51118, 51067, 51037, 51020, 51011, 50997,
    50945, 50903, 50887, 50854, 50849, 50836, 50835, 50834, 50833, 50831, 50815, 50809, 50787, 50733, 50692, 50585,
    50577, 50576, 50545, 50529, 50513, 50356, 50277, 50258, 50246, 50224, 50205, 50202, 50198, 50189, 50101, 50040,
    50019, 50016, 49927, 49803, 49765, 49762, 49751, 49678, 49603, 49597, 49522, 49521, 49520, 49519, 49500, 49498,
    49452, 49398, 49372, 49352, 49302, 49275, 49241, 49235, 49232, 49228, 49216, 49213, 49211, 49204, 49203, 49202,
    49201, 49197, 49196, 49191, 49190, 49189, 49179, 49173, 49172, 49170, 49169, 49166, 49132, 49048, 49002, 48973,
    48967, 48966, 48925, 48813, 48783, 48682, 48648, 48631, 48619, 48434, 48356, 48167, 48153, 48127, 48083, 48067,
    48009, 47969, 47966, 47860, 47858, 47850, 47806, 47777, 47700, 47634, 47624, 47595, 47581, 47567, 47448, 47372,
    47348, 47267, 47197, 47119, 47029, 47012, 46992, 46813, 46593, 46436, 46418, 46372, 46310, 46182, 46171, 46115,
    46069, 46034, 45960, 45864, 45777, 45697, 45624, 45602, 45463, 45438, 45413, 45226, 45220, 45164, 45136, 45050,
    45038, 44981, 44965, 44711, 44704, 44628, 44616, 44541, 44505, 44479, 44431, 44410, 44380, 44200, 44119, 44101,
    44004, 43868, 43823, 43734, 43690, 43654, 43425, 43242, 43231, 43212, 43143, 43139, 43103, 43027, 43018, 43002,
    43000, 42990, 42906, 42735, 42685, 42679, 42675, 42632, 42590, 42575, 42560, 42559, 42452, 42449, 42322, 42276,
    42251, 42158, 42127, 42035, 42001, 41808, 41795, 41794, 41773, 41632, 41551, 41442, 41398, 41348, 41345, 41342,
    41318, 41281, 41250, 41142, 41123, 40951, 40834, 40812, 40754, 40732, 40712, 40628, 40614, 40513, 40489, 40457,
    40400, 40393, 40306, 40011, 40005, 40003, 40002, 40001, 39917, 39895, 39883, 39869, 39795, 39774, 39763, 39732,
    39630, 39489, 39482, 39433, 39380, 39293, 39265, 39117, 39067, 38936, 38805, 38780, 38764, 38761, 38570, 38561,
    38546, 38481, 38446, 38358, 38331, 38313, 38270, 38224, 38205, 38194, 38029, 37855, 37789, 37777, 37674, 37647,
    37614, 37607, 37522, 37393, 37218, 37185, 37174, 37151, 37121, 36983, 36962, 36950, 36914, 36824, 36823, 36748,
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
    let mut high_frequency_ports = BTreeSet::new();

    for &port in combined_high_frequency_ports() {
        if (range.start..=range.end).contains(&port) {
            high_frequency_ports.insert(port);
        }
    }

    let mut ordered_ports: Vec<u16> = high_frequency_ports.iter().copied().collect();

    for port in range.start..=range.end {
        if !high_frequency_ports.contains(&port) {
            ordered_ports.push(port);
        }
    }

    ordered_ports
}

fn build_high_frequency_manual(manual_ports: &[u16]) -> Vec<u16> {
    let mut high_frequency_ports = BTreeSet::new();
    let manual_set: HashSet<u16> = manual_ports.iter().copied().collect();

    for &port in combined_high_frequency_ports() {
        if manual_set.contains(&port) {
            high_frequency_ports.insert(port);
        }
    }

    let mut ordered_ports: Vec<u16> = high_frequency_ports.iter().copied().collect();

    let mut remaining_ports = BTreeSet::new();
    for &port in manual_ports {
        if !high_frequency_ports.contains(&port) {
            remaining_ports.insert(port);
        }
    }

    ordered_ports.extend(remaining_ports);

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
        assert!(result.windows(2).all(|w| w[0] <= w[1]));
        assert_eq!(result, vec![22, 8080, 9000, 9999]);
    }

    #[test]
    fn high_frequency_range_orders_priority_then_remaining() {
        use std::collections::HashSet;

        let high_frequency_ports: HashSet<u16> =
            super::combined_high_frequency_ports().copied().collect();

        let mut priority_ports = Vec::new();
        let mut remaining_ports = Vec::new();

        for port in 1..=1000 {
            if high_frequency_ports.contains(&port) {
                priority_ports.push(port);
            } else {
                remaining_ports.push(port);
            }

            if priority_ports.len() >= 2 && remaining_ports.len() >= 2 {
                break;
            }
        }

        let mut all_ports = priority_ports.clone();
        all_ports.extend(remaining_ports.clone());
        let start = *all_ports.iter().min().expect("range should not be empty");
        let end = *all_ports.iter().max().unwrap();

        let range = PortRange { start, end };
        let strategy = PortStrategy::pick(&PortSelection::Range(range), ScanOrder::HighFrequency);
        let result = strategy.order();

        let first_non_priority = result
            .iter()
            .position(|port| !high_frequency_ports.contains(port))
            .expect("range should contain non-priority ports");

        assert!(
            first_non_priority > 0,
            "expected priority ports to be first"
        );

        assert!(
            result[..first_non_priority]
                .windows(2)
                .all(|w| w[0] <= w[1]),
            "priority ports should be sorted"
        );

        let remainder = &result[first_non_priority..];

        assert!(
            remainder
                .iter()
                .all(|port| !high_frequency_ports.contains(port)),
            "remainder should not contain priority ports"
        );

        assert!(
            remainder.windows(2).all(|w| w[0] <= w[1]),
            "remainder should be sorted"
        );
    }

    #[test]
    fn high_frequency_manual_orders_priority_then_remaining() {
        use std::collections::HashSet;

        let high_frequency_ports: HashSet<u16> =
            super::combined_high_frequency_ports().copied().collect();

        let mut priority_ports = Vec::new();
        let mut remaining_ports = Vec::new();

        for port in 1..=1000 {
            if high_frequency_ports.contains(&port) {
                priority_ports.push(port);
            } else {
                remaining_ports.push(port);
            }

            if priority_ports.len() >= 2 && remaining_ports.len() >= 2 {
                break;
            }
        }

        let mut manual_ports = Vec::new();
        manual_ports.extend(priority_ports.iter().copied());
        manual_ports.extend(remaining_ports.iter().copied());

        let strategy =
            PortStrategy::pick(&PortSelection::List(manual_ports), ScanOrder::HighFrequency);
        let result = strategy.order();

        let first_non_priority = result
            .iter()
            .position(|port| !high_frequency_ports.contains(port))
            .expect("manual list should contain non-priority ports");

        assert!(
            first_non_priority > 0,
            "expected priority ports to be first"
        );

        assert!(
            result[..first_non_priority]
                .windows(2)
                .all(|w| w[0] <= w[1]),
            "priority ports should be sorted"
        );

        let remainder = &result[first_non_priority..];

        assert!(
            remainder
                .iter()
                .all(|port| !high_frequency_ports.contains(port)),
            "remainder should not contain priority ports"
        );

        assert!(
            remainder.windows(2).all(|w| w[0] <= w[1]),
            "remainder should be sorted"
        );
    }
}
