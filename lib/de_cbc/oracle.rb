require 'de_cbc'

#
# Wraps a CBC padding oracle.
#
# A padding oracle command must read two consecutive CBC blocks on
# STDIN, then write a 0 byte on STDOUT if decrypting the second block
# using the first block as an IV was successful, or a 1 byte on STDOUT
# in the event of a padding error. It must repeat doing so until STDIN
# is closed.
#
class DeCBC::Oracle
  #
  # Executes +command+ and yields an instance of the Oracle, ready to
  # verify the padding-correctness of block pairs.
  #
  def self.open(command)
    Open3.popen3(command) do |stdin, stdout, stderr, thread|
      begin
        yield new(stdin, stdout, stderr)
      ensure
        stdin.close
        thread.join
      end
    end
  end

  #
  # Returns whether or not the +block+ has valid padding when decrypted
  # with the +iv+.
  #
  def valid?(iv, block)
    stdin.write(iv)
    stdin.write(block)
    stdin.flush

    stdout.read(1) == "\x00"
  end

  protected

  def initialize(stdin, stdout, stderr)
    self.stdin  = stdin
    self.stdout = stdout
    self.stderr = stderr
  end

  private_class_method :new

  attr_accessor :stdin
  attr_accessor :stdout
  attr_accessor :stderr
end
