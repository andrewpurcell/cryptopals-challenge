require 'rspec'
require 'set'
require 'pp'
require 'pry'
require 'base64'

module Conversions
  BASE64_CHARS = ['A'..'Z', 'a'..'z', '0'..'9', ['+', '/']].map(&:to_a).flatten

  def hex_to_base64(hex, alphabet=BASE64_CHARS)
    hex.chars
      .map { |c| c.to_i(16) }
      .each_slice(3)
      .map { |(a, b, c)|
        [a << 2 | b >> 2, ((b & 3) << 4) | c].map { |char| alphabet[char] }
      }.join('')
  end

  def hex_to_bytes(input)
    input.chars.map { |c| c.to_i(16) }.each_slice(2).map { |(a,b)| (a<<4) | b }
  end

  def bytes_to_hex(bytes)
    bytes.map { |b| sprintf "%02x", b }.join ''
  end
end

def fixed_xor(input, xor_key)
  hex_to_bytes(input)
    .zip(hex_to_bytes(xor_key))
    .map { |s,k| s ^ k }
    .map { |b| b.to_s(16) }
    .join('')
end

describe 'challenge 1' do
  include Conversions
  it 'converts hex to base 64' do
    expect(
      hex_to_base64('49276d206b696c6c696e6720796f757220627261696e206c696b65206120706f69736f6e6f7573206d757368726f6f6d')
    ).to eq 'SSdtIGtpbGxpbmcgeW91ciBicmFpbiBsaWtlIGEgcG9pc29ub3VzIG11c2hyb29t'
  end
end

describe 'challenge 2' do
  include Conversions
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
  include Conversions

  def decrypt(bytes)
    # possible values for the 1-char xor key
    candidates = 32..126

    candidates
      .map { |key| bytes.map { |b| b ^ key }.pack('c*') }
      .min_by { |str| score(str) }
  end

  def find_key(bytes)
    candidates = 32..126

    candidates
      .map { |key| [key, bytes.map { |b| b ^ key }.pack('c*')] }
      .min_by { |key, str| character_frequency(str) }
      .first
  end

  def find_xored_needle(haystack_file)
    File
      .readlines(haystack_file)
      .map { |line|
        line.chomp!
        decrypted = decrypt(hex_to_bytes(line))
        _score = score(decrypted)
        [line, decrypted, _score]
      }
      .sort_by { |processed| processed.last }
      .first.slice(0,2)
  end

  def repeated_xor(bytes, key:)
    bit = key.bytes.cycle

    bytes.map { |b| b ^ bit.next }
  end

  def hamming(s1, s2)
    s1.zip(s2).reduce(0) do |distance, (a,b)|
      distance + (a^b).to_s(2).count('1')
    end
  end

  def crack_repeating_key_xor(bytes, size_range)
    decrypter = Decrypter.new

    top_keysizes = size_range.reduce({}) do |diffs, key_size|
      a, b = bytes.slice(0, key_size), bytes.slice(key_size, key_size)
      diffs[key_size] = hamming(a, b) / key_size.to_f
      diffs
    end.sort_by { |k,v| v }
    .tap { |k,v| next; pp "k #{k}, v #{v}"}
    .take(1)
    .map(&:first)

    top_keysizes
      .map do |key_size|
        empty_list = key_size.times.map { [] }
        blocks = bytes.each_with_index.reduce(empty_list) do |blocks, (b, i)|
          blocks[i % key_size] << b
          blocks
        end

        blocks
        .tap { |blocks| puts blocks.first.take(20).join(',') }
        .map { |block| decrypter.find_key(block) }
        .pack('c*')
        .tap do |key|
          puts "key candidate: #{key}"
        end
        .tap do |key|
          puts "test #{key}: #{safe_print(decrypter.repeated_xor(bytes.take(50), key: key).pack('c*'))}"
        end
      end
  end
end


describe 'challenge 3' do
  include Conversions
  it 'decrypts' do
    expect(
      Decrypter.new.decrypt(hex_to_bytes('1b37373331363f78151b7f2b783431333d78397828372d363c78373e783a393b3736'))
    ).to eq "Cooking MC's like a pound of bacon"
  end

  it 'decrypts the next challenge' do
    expect(
      Decrypter.new.decrypt(hex_to_bytes('7b5a4215415d544115415d5015455447414c155c46155f4058455c5b523f'))
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


describe 'challenge 5' do
  include Conversions
  it 'does repeating key xor' do
    expect(
      bytes_to_hex(
        Decrypter.new.repeated_xor("Burning 'em, if you ain't quick and nimble\nI go crazy when I hear a cymbal".bytes,
                     key: 'ICE')
      )
    ).to eq '0b3637272a2b2e63622c2e69692a23693a2a3c6324202d623d63343c2a26226324272765272' +
            'a282b2f20430a652e2c652a3124333a653e2b2027630c692b20283165286326302e27282f'
  end
end

describe 'challenge 6' do
  it 'computes hamming distance' do
    expect(
      Decrypter.new.hamming('this is a test'.bytes, 'wokka wokka!!!'.bytes)
    ).to eq 37
  end

  it 'works', :focus do
    expect(
      Decrypter.new.crack_repeating_key_xor(
        [17, 0, 31, 21, 10, 83, 14, 10, 1, 21, 1],
        2..5)
    ).to eq 'yes'
  end

  let(:bytes) do
    Base64.decode64(File.read('s1c6_data.txt')).bytes
  end

  it 'cracks stuff', :focus do
    expect(
      Decrypter.new.crack_repeating_key_xor(bytes, 2..40)
    ).to eq 'ABCDEF'
  end
end
