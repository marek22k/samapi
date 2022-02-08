
# Copyright 2022 Marek Küthe
# GNU GPLv3

# This program can transfer a file from one device to another.
# For this it uses two tunnel, a backup tunnel each of a length of one hop.
# This can be changed in the source code.
# Requires gems: base32, base_x

require "base64"
require "base32"
require "base_x"
require "openssl"
require "securerandom"
require_relative "samapi.rb"

$chunk_size = 4 * 1024

def set_status status
  if status[0]
    puts "Status = OK"
  else
    puts "Error = #{status[-1][:args].values.join " "}"
    puts "About!"
    exit!
  end
end

def privkey_to_hash priv_key
  priv_key = priv_key.tr "-~", "+/"
  # conversion of base64 alphabet from i2p to standard
  
  priv_bin = Base64.decode64 priv_key
  # decode the private key
  
  cert_len = priv_bin[385...387].unpack("S>")[0]
  # determining the length of the certificate, others are constants for this case
  pub_len = 256 + 128 + 1 + 2 + cert_len
  # see https://geti2p.net/spec/common-structures#keysandcert
  # calculation of the length of the public part / destination
  
  hash = OpenSSL::Digest::SHA256.digest priv_bin[0...pub_len]
  
  return hash
end

def encode_hash hash, passwd = "\0\0\0\0\0"
  passwd.length == 5 or raise ArgumentError.new("Passwd must have length 5")
  
  bin = passwd + hash
  checksum = bin.bytes.reduce(0, :+) % 10
  checksum_bin = [checksum].pack("C")
  bin = checksum_bin + bin
  b36 = BaseX.encode(bin, numerals: "0123456789abcdefghijkmnopqrstuvwxyz").chars

  return b36.each_slice(4).map(&:join)
end

def decode_hash codes
  bin = BaseX.decode(codes, numerals: "0123456789abcdefghijkmnopqrstuvwxyz")
  
  checksum_bin = bin[0]
  checksum = checksum_bin.unpack("C")[0]
  passwd = bin[1...6]
  hash = bin[6..-1]
  calc_checksum = bin[1..-1].bytes.reduce(0, :+) % 10
  
  return [checksum == calc_checksum, passwd, hash]
end

def hash_to_b32 hash
  return Base32.encode(hash).tr("=", "").downcase + ".b32.i2p"
end

def display_transfercode code
  tf = (code.map { |code_block|
    code_block.upcase
  }).join " "

  puts "TRANSFER CODE: TF #{tf}"
end

if ARGV[0]
  id = "BeamBotSender#{Random.rand 100}"
  
  if ! File.readable? ARGV[0]
    puts "Error = File to send unreadable."
    exit!
  end
  
  puts "Task = Calculating checksum for file"
  file_checksum = OpenSSL::Digest::MD5.file(ARGV[0]).hexdigest
  
  puts "Task = Preparing i2p session"
  control = SamApi.new
  set_status control.handshake
  comm = SamApi.new
  set_status comm.handshake

  passwd = SecureRandom.random_bytes(5)
  
  puts "Task = Preparing serving of file"
  server = TCPServer.new "127.0.0.1", 0
  Thread.new do
    loop {
      Thread.new(server.accept) { |socket|
        header = socket.gets.chomp.split " "
        b32 = hash_to_b32 privkey_to_hash header[0]
        puts "Request from #{b32}"
        in_passwd = socket.read 5
        if in_passwd == passwd
          socket.puts File.basename ARGV[0]
          socket.puts file_checksum
          puts "#{b32} has successfully authenticated"
          fil = File.open ARGV[0], "rb"
          while ! fil.eof?
            socket.write fil.read $chunk_size
          end
          fil.close
        else
          puts "WARNING - #{b32} did not authenticate successfully."
        end
        socket.close
      }
    }
  end

  host = server.addr[3]
  port = server.addr[1]

  puts "Task = Preparing i2p session"
  res = control.session_create(
    "STYLE" => "STREAM",
    "ID" => id,
    "DESTINATION" => "TRANSIENT",
    "SIGNATURE_TYPE" => "EdDSA_SHA512_Ed25519",
    "inbound.length" => "1",
    "outbound.length" => "1",
    "inbound.quantity" => "2",
    "outbound.quantity" => "2",
    "inbound.backupQuantity" => "1",
    "outbound.backupQuantity" => "1"
  )
  priv_key = res[1]
  set_status res

  set_status comm.stream_forward(
    "ID" => id,
    "PORT" => port,
    "HOST" => host,
    "SILENT" => false
  )

  hash = privkey_to_hash priv_key
  transfercode = encode_hash hash, passwd
  display_transfercode transfercode

  loop {
    control.check_ping
    comm.check_ping
    status = control.send_ping and comm.send_ping
    if ! status
      puts "Warning = No ping"
    end
    sleep 10
  }
else
  id = "BeamBotRecipent#{Random.rand 100}"
  
  puts "Task = Preparing i2p session"
  control = SamApi.new
  set_status control.handshake

  puts "Task = Preparing i2p session"
  res = control.session_create(
    "STYLE" => "STREAM",
    "ID" => id,
    "DESTINATION" => "TRANSIENT",
    "SIGNATURE_TYPE" => "EdDSA_SHA512_Ed25519",
    "inbound.length" => "1",
    "outbound.length" => "1",
    "inbound.quantity" => "2",
    "outbound.quantity" => "2",
    "inbound.backupQuantity" => "1",
    "outbound.backupQuantity" => "1"
  )
  set_status res
  
  print "Transfer code: TF "
  STDOUT.flush
  tf = gets.chomp
  tf = tf.tr(" ", "").downcase
  res = decode_hash tf
  if ! res[0]
    puts "Warning = Mismatch checksum"
  end
  passwd = res[1]
  hash = res[2]
  b32 = hash_to_b32 hash
  puts "Task = Determine exact destination"
  lookup_result = control.naming_lookup b32
  set_status lookup_result
  b64 = lookup_result[1]
  
  control.check_ping

  puts "Task = Connect to destination"
  comm = SamApi.new
  set_status comm.handshake
  stream = comm.stream_connect(
    "ID" => id,
    "DESTINATION" => b64
  )
  set_status stream
  
  puts "Info = Connected"
  socket = stream[1]
  puts "Task = Authenticating"
  passwd = "12345"
  socket.write passwd
  socket.flush
  if socket.closed? or socket.eof?
    puts "Info = Authentication failed"
  else
    puts "Info = Authentication successful"
    puts "Task = Receive file"
    filename = socket.gets.chomp
    file_checksum = socket.gets.chomp
    filename = "recived_#{filename}"
    fil = File.new filename, "wb"
    print "Task = Receive chunks"
    STDOUT.flush
    while ! socket.eof?
      fil.write socket.read $chunk_size
      print "."
      STDOUT.flush
    end
    fil.close
    puts
    puts "Task = Checking the file for corruption"
    calc_checksum = OpenSSL::Digest::MD5.file(filename).hexdigest
    pp file_checksum
    pp calc_checksum
    if calc_checksum == file_checksum
      puts "Info = The file was received successfully"
    else
      puts "Warning = The file was received corrupted"
    end
    puts
  end
end
