require 'rspec'

BASE64_CHARS = ['A'..'Z', 'a'..'z', '0'..'9', ['+', '/']].map(&:to_a).flatten

def convert(hex, alphabet=BASE64_CHARS)
  hex.chars
    .map { |c| c.to_i(16) }
    .each_slice(3)
    .map { |(a, b, c)|
      [a << 2 | b >> 2, ((b & 3) << 4) | c].map { |char| alphabet[char] }
    }.join('')
end

def decode_hex_to_bytes(input)
  input.chars.map { |c| c.to_i(16) }.each_slice(2).map { |(a,b)| (a<<4) | b }
end

def fixed_xor(input, xor_key)
  decode_hex_to_bytes(input)
    .zip(decode_hex_to_bytes(xor_key))
    .map { |s,k| s ^ k }
    .map { |b| b.to_s(16) }
    .join('')
end

describe 'challenge 1' do
  it 'converts hex to base 64' do
    expect(
      convert('49276d206b696c6c696e6720796f757220627261696e206c696b65206120706f69736f6e6f7573206d757368726f6f6d')
    ).to eq 'SSdtIGtpbGxpbmcgeW91ciBicmFpbiBsaWtlIGEgcG9pc29ub3VzIG11c2hyb29t'
  end
end

describe 'challenge 2' do
  it 'xors' do
    expect(
      fixed_xor(
        '1c0111001f010100061a024b53535009181c',
        '686974207468652062756c6c277320657965'
      )
    ).to eq '746865206b696420646f6e277420706c6179'
  end
end
