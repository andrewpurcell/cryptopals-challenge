require 'rspec'
require 'set'
require 'pp'

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

module EnglishChecker
  CHAR_FREQUENCIES = {"a"=>0.08167, "b"=>0.01492, "c"=>0.02782, "d"=>0.04253, "e"=>0.12702,
                      "f"=>0.02228, "g"=>0.02015, "h"=>0.06094, "i"=>0.06966, "j"=>0.00153,
                      "k"=>0.00772, "l"=>0.04025, "m"=>0.02406, "n"=>0.06749, "o"=>0.07507,
                      "p"=>0.01929, "q"=>0.00095, "r"=>0.05987, "s"=>0.06327, "t"=>0.09056,
                      "u"=>0.02758, "v"=>0.00978, "w"=>0.0236, "x"=>0.0015, "y"=>0.01974,
                      "z"=>0.00074}

  def printable?(str)
    # 9, 10 are \n and \t
    str.bytes.all? { |b| (32..126).cover?(b) || [9, 10].include?(b) }
  end

  def character_frequency(input)
    range = 'a'..'z'
    # assertion to make sure we can't divide by zero
    raise unless range.to_a == CHAR_FREQUENCIES.keys

    valid = input.downcase.chars.select { |c| range.cover? c }

    return Float::INFINITY unless valid.length > 0

    freq_map = range.map { |c| [c, 0] }.to_h
    # chi^2 error calculation
    valid
      .reduce(freq_map) { |a, c|
        a[c] += 1
        a
      }.map { |c, freq|
        [c, freq.to_f / valid.length]
      }.map { |c, f|
        x = ((f - CHAR_FREQUENCIES[c])**2) / (CHAR_FREQUENCIES[c])
      }.reduce(:+)
  end

  def avg_word_length(input)
    word_counts = input.split(/\s+/).map(&:length)
    ((word_counts.reduce(:+).to_f / word_counts.length) - 5.1).abs
  end

  def all_printable_score(input)
    printable?(input) ? -2.0 : 1
  end

  def safe_print(str)
    str.gsub(/([^a-zA-Z0-9 ])/, '*')
  end

  def score(input, debug=false)
    [
      :character_frequency,
      :avg_word_length,
      :all_printable_score
    ].reduce({}) { |memo, scorer|
      memo[scorer] = send(scorer, input)
      memo
    }.tap { |composite|
      next unless debug

      puts "#{safe_print(input)}: #{composite.inspect}"
    }.values.reduce(:+)
  end
end

class Decrypter
  include EnglishChecker

  def decrypt(input)
    bytes = decode_hex_to_bytes(input)
    # possible values for the 1-char xor key
    candidates = 32..126

    candidates
      .map { |key| bytes.map { |b| b ^ key }.pack('c*') }
      .min_by { |str| score(str) }
  end

  def find_xored_needle(haystack_file)
    File
      .readlines(haystack_file)
      .map { |line|
        line.chomp!
        decrypted = decrypt(line)
        _score = score(decrypted)
        [line, decrypted, _score]
      }
      .sort_by { |processed| processed.last }
      .first.slice(0,2)
  end
end


describe 'challenge 3' do
  it 'decrypts' do
    expect(
      Decrypter.new.decrypt('1b37373331363f78151b7f2b783431333d78397828372d363c78373e783a393b3736')
    ).to eq "Cooking MC's like a pound of bacon"
  end

  it 'decrypts the next challenge' do
    expect(
      Decrypter.new.decrypt('7b5a4215415d544115415d5015455447414c155c46155f4058455c5b523f')
    ).to eq "Now that the party is jumping\n"
  end
end

describe 'challenge 4' do
  it 'finds the right line' do
    expect(
      Decrypter.new.find_xored_needle('s1c4_data.txt')
    ).to eq ['7b5a4215415d544115415d5015455447414c155c46155f4058455c5b523f',
             "Now that the party is jumping\n"]
  end
end
