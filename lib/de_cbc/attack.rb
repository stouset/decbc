require 'de_cbc'

class DeCBC::Attack
  def initialize(oracle, ciphertext, blocksize)
    raise ArgumentError unless
      ciphertext.encoding == Encoding::ASCII_8BIT

    raise ArgumentError unless
      ciphertext.length % blocksize == 0

    self.oracle    = oracle
    self.blocksize = blocksize
    self.blocks    = ciphertext.scan %r{ .{#{blocksize}} }x
  end

  def plaintext
    plaintext = payload
    plaintext[0..-plaintext[-1].ord.succ]
  end

  protected

  attr_accessor :oracle
  attr_accessor :blocks
  attr_accessor :blocksize

  private

  def payload
    blocks.each_cons(2).map do |(iv, ciphertext)|
      1.upto(self.blocksize).each_with_object(
        Array.new(self.blocksize)
      ) do |pad, plaintext|
        offset = self.blocksize - pad

        # replace solved parts of the IV with ones that XOR to the next
        # attempted pad
        repad_iv(iv, offset, pad)

        # decrypt a single byte of the plaintext
        plaintext[offset] = decrypt_byte(
          iv,
          ciphertext,
          offset,
          pad
        )

        # replace the IV at the solved offest with one that generates
        # the currently-attempted pad
        iv[offset] = (iv[offset].ord ^ plaintext[offset].ord ^ pad).chr
      end
    end.flatten.join
  end

  def repad_iv(iv, offset, pad)
    (offset.succ ... iv.length).each do |i|
      iv[i] = (iv[i].ord ^ (pad - 1) ^ pad).chr
    end
  end

  def decrypt_byte(iv, block, offset, pad)
    iv       = iv.dup
    original = iv[offset].ord

    iv[offset]

    correct = 256.times.detect do |i|
      next if
        i == original

      iv[offset] = i.chr

      self.oracle.valid?(iv, block)
    end

    (original ^ (correct || original) ^ pad).chr
  end
end
