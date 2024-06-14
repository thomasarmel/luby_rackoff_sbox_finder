use std::collections::HashSet;

const GOOD_RULES: [u32; 53] = [679329300, 619167105, 1222368018, 628354122, 1172536362, 773318772, 708688980, 775731285, 1198624440, 661818840, 844880460, 1897392270, 1898440845, 1289378610, 1396333770, 1401642168, 3284380245, 1306798002, 1323575154, 1323833202, 3800985885, 1846009974, 1430039610, 1931106510, 1437219900, 1438886595, 3310595130, 1440924555, 3899928087, 388748520, 2971134093, 2971392141, 395039208, 3906218775, 1960980039, 2988169293, 2747938140, 2747974485, 3005588685, 2765924115, 2118260955, 3072599277, 495696081, 2898633525, 2881566813, 2915578203, 2363860785, 3521648523, 2448957321, 3586278315, 3450086835, 2397575025, 3615637995];
const RING_SIZE: usize = 5;
const SBOX_SIZE: usize = RING_SIZE * 2;
const FUNCTION_INPUT_SIZE: usize = 5;
const GOOD_BIJECTIVE_RULE_NUMBER: u32 = 1438886595;

// Dire 7 tours: https://iacr.org/archive/crypto2003/27290510/27290510.pdf
// Melange affine: essentiel pr eliminer le cas 1023 0b1111111111
// https://github.com/PoustouFlan/SUnbox

fn main() {
    //let mut output_set = HashSet::new();
    for i in /*0..(1 << (SBOX_SIZE - 3))*/0..(1 << SBOX_SIZE) {

        /*println!("\\textbf{{0x{:03x}}} & 0x{:03x} & \\textbf{{0x{:03x}}} & 0x{:03x} & \\textbf{{0x{:03x}}} & 0x{:03x} & \\textbf{{0x{:03x}}} & 0x{:03x} & \\textbf{{0x{:03x}}} & 0x{:03x} & \\textbf{{0x{:03x}}} & 0x{:03x} & \\textbf{{0x{:03x}}} & 0x{:03x} & \\textbf{{0x{:03x}}} & 0x{:03x}\\\\",
                 i, calc_sbox_value(i),
                 i+128, calc_sbox_value(i+128),
                 i+256, calc_sbox_value(i+256),
                 i+384, calc_sbox_value(i+384),
                 i+512, calc_sbox_value(i+512),
                 i+640, calc_sbox_value(i+640),
                 i+768, calc_sbox_value(i+768),
                 i+896, calc_sbox_value(i+896),
        );*/

        let output_unsigned = calc_sbox_value(i);
        println!("{},", output_unsigned);
        //output_set.insert(output_unsigned);
    }
    //println!("Output set size: {}", output_set.len());
}

fn calc_sbox_value(input: usize) -> usize {
    let input_bits: [bool; SBOX_SIZE] = unsigned_to_bool_array::<SBOX_SIZE>(input);
    let round_1 = pair_wise_permutation(input_bits, 5, 3);
    let round_2 = do_lr_round(round_1, GOOD_BIJECTIVE_RULE_NUMBER);
    let round_3 = do_lr_round(round_2, GOOD_BIJECTIVE_RULE_NUMBER);
    let round_4 = do_lr_round(round_3, GOOD_BIJECTIVE_RULE_NUMBER);
    let round_5 = do_lr_round(round_4, GOOD_BIJECTIVE_RULE_NUMBER);
    let round_6 = pair_wise_permutation(round_5, 7, 11);
    let round_7 = do_lr_round(round_6, GOOD_BIJECTIVE_RULE_NUMBER);
    let round_8 = do_lr_round(round_7, GOOD_BIJECTIVE_RULE_NUMBER); // ?
    let round_9 = do_lr_round(round_8, GOOD_BIJECTIVE_RULE_NUMBER); // ?
    let round_10 = pair_wise_permutation(round_9, 13, 17);
    let round_11 = do_lr_round(round_10, GOOD_BIJECTIVE_RULE_NUMBER);
    bool_array_to_unsigned::<SBOX_SIZE>(round_11)
}

fn do_lr_round(input_bits: [bool; SBOX_SIZE], rule_number: u32) -> [bool; SBOX_SIZE] {
    let l0: [bool; RING_SIZE] = input_bits[0..RING_SIZE].try_into().unwrap();
    let r0: [bool; RING_SIZE] = input_bits[RING_SIZE..SBOX_SIZE].try_into().unwrap();
    let f1 = get_new_ring(r0, rule_number);
    let l1 = r0;
    let r1 = xor_bool_arrays::<RING_SIZE>(l0, f1);
    [l1, r1].concat().as_slice().try_into().unwrap()
}

fn pair_wise_permutation(input_bits: [bool; SBOX_SIZE], a: usize, b: usize) -> [bool; SBOX_SIZE] {
    let unsigned_input = bool_array_to_unsigned::<SBOX_SIZE>(input_bits);
    let unsigned_output = ((unsigned_input * a) + b) % (1 << SBOX_SIZE);
    unsigned_to_bool_array::<SBOX_SIZE>(unsigned_output)
}

#[inline(always)]
fn unsigned_to_bool_array<const S: usize>(number: usize) -> [bool; S] {
    let mut bits = [false; S];
    for i in 0..S {
        bits[i] = (number & (1 << i)) != 0;
    }
    bits
}

#[inline(always)]
fn bool_array_to_unsigned<const S: usize>(bits: [bool; S]) -> usize {
    let mut number = 0;
    for i in 0..S {
        if bits[i] {
            number |= 1 << i;
        }
    }
    number
}

#[inline(always)]
fn compute_ca_rule(rule_number: u32, input_bits: u8) -> bool {
    return (rule_number & (1 << input_bits)) != 0;
}

fn get_new_ring(ring: [bool; RING_SIZE], rule_number: u32) -> [bool; RING_SIZE] {
    let mut new_ring = [false; RING_SIZE];
    for i in 0..RING_SIZE {
        let input_bits = (ring[(i + RING_SIZE - 2) % RING_SIZE] as u8) << 4
            | (ring[(i + RING_SIZE - 1) % RING_SIZE] as u8) << 3
            | (ring[i] as u8) << 2
            | (ring[(i + 1) % RING_SIZE] as u8) << 1
            | ring[(i + 2) % RING_SIZE] as u8;
        new_ring[i] = compute_ca_rule(rule_number, input_bits);
    }
    new_ring
}

fn xor_bool_arrays<const S: usize>(a: [bool; S], b: [bool; S]) -> [bool; S] {
    let mut result = [false; S];
    for i in 0..S {
        result[i] = a[i] ^ b[i];
    }
    result
}

#[allow(dead_code)]
fn get_good_bijective_rules() {
    let bijective_rules = GOOD_RULES.into_iter().filter(|&rule| {
        let mut output_set = HashSet::new();
        for i in 0..(1 << RING_SIZE) {
            let bits = unsigned_to_bool_array::<RING_SIZE>(i);
            let output = get_new_ring(bits, rule as u32);
            let output_unsigned = bool_array_to_unsigned::<RING_SIZE>(output);
            output_set.insert(output_unsigned);
        }
        if output_set.len() == (1 << RING_SIZE) {
            println!("Bijective rule: {}", rule);
        }
        output_set.len() == (1 << RING_SIZE)
    }).collect::<HashSet<u32>>();
    println!("Bijective rules: {}", bijective_rules.len());
}
