#!/usr/bin/env ruby
# Brad Beacham 2018
#
#####################################################################################
# INFORMATION
# https://beacham.online/
#
# Simplifies and ensures standard enumeration of web services by performing Nikto and Wfuzz scans
#
#####################################################################################

#####################################################################################
# Required Gems:
require 'optparse'
require 'pathname'
require 'thread'
require 'thwait'
require 'highline/import'
# gem install highline -v 1.7.8

#####################################################################################
# Script switches section
$options = {}

ARGV << '-h' if ARGV.empty?

OptionParser.accept(Pathname) do |pn|
  begin
    Pathname.new(pn) if pn
    # code to verify existence
  rescue ArgumentError
    raise OptionParser::InvalidArgument, s
  end
end
 
optparse = OptionParser.new do|opts|
  # Set a banner, displayed at the top
  # of the help screen.
  opts.banner = "Usage: inqHTTP.rb"

   # Define the $options, and what they do
  $options[:directory] = false
   opts.on( '-d', '--output-dir <FILE>',Pathname, 'Specify the directory to save all output' ) do|file|
     $options[:directory] = file
   end
 
  $options[:host] = nil
  opts.on( '-i <HOST>', 'Specify individual host to perform enumeration against' ) do|input|
    $options[:host] = input
  end
 
  $options[:inputList] = nil
  opts.on( '-l', '--input-list <FILE>',Pathname, 'File containing one host per line to read from (NO SUBNETS!!!!)' ) do|file|
    $options[:inputList] = File.absolute_path(file)
  end

  $options[:threads] = 1
  opts.on( '-t [1-10]', '--threads [1-10]',Integer, 'Specify the number of concurrent scans to perform') do|int|
    if int > 0 && int < 11
      $options[:threads] = int
    elsif int > 10
      $options[:threads] = 10
    else
      $options[:threads] = 1
    end
  end

  $options[:type] = nil
  opts.on( '-t [ fuzz | nikto ]', 'Perform individual function, rather than both' ) do|input|
    $options[:type] = input
  end

  $options[:fuzzer] = nil
  opts.on( '-f [ wfuzz | gobuster ]', 'Wfuzz or Gobuster? Defualt is both!' ) do|input|
    $options[:fuzzer] = input
  end

  $options[:noColour] = false
  opts.on( '--no-colour', 'Removes colourisation from the ourput' ) do
    $options[:noColour] = true
  end
 
   # This displays the help screen, all programs are assumed to have this option.
  opts.on( '-h', '--help', 'Display this screen' ) do
    puts "inqHTTP, the ruby based enumeration script!"
    puts "This tool is a wrapper for various other tools included within Kali linux.  This will streamline enumeration and help you on your way to getting mad $hellz"
    puts
    puts opts
    puts
    exit
  end 
end.parse!

#####################################################################################
# Appends notifications to the start of text (ie. [*], [+], etc)
class String
  if $options[:noColour]
    def error;        "[!] #{self}" end
    def fail;         "[-] #{self}" end
    def success;      "[+] #{self}" end
    def event;        "[*] #{self}" end
    def debug;        "[%] #{self}" end
    def notification; "[-] #{self}" end
  else
      def error;        "\e[31m[!]\e[0m #{self}" end        # [!] Red
      def fail;         "\e[31m[-]\e[0m #{self}" end		  # [-] Red
      def success;      "\e[32m[+]\e[0m #{self}" end        # [+] Green
      def event;        "\e[34m[*]\e[0m #{self}" end        # [*] Blue
      def debug;        "\e[35m[%]\e[0m #{self}" end        # [%] Magenta
      def notification; "[-] #{self}" end                   # [-]
  end
 end

 # Input validation on user input
 if $options[:host].to_s.empty? && $options[:inputList].to_s.empty?
  puts "ERROR: Please select host (-i) or input file (-l/--input-list)".error
  abort()
end 

if $options[:host] && $options[:inputList]
  puts "ERROR: Please choose only host (-i) or input file (-l/--input-list)".error
  abort()
end 

$threads = $options[:threads]

directory = nil
if !$options[:directory]
  $directory = Dir.pwd
else
  $directory = $options[:directory]
end

#####################################################################################
# Setup the hosts to scan.
if $options[:inputList]
  $input = File.readlines("#{$options[:inputList]}")
  $input = $input.collect{|x| x.strip || x }
else
  $input = Array.new
  $input.push $options[:host]
end

#####################################################################################
# Thread pool function
class ThreadPool
  def initialize(max_threads = 10)
    @pool = SizedQueue.new(max_threads)
    max_threads.times{ @pool << 1 }
    @mutex = Mutex.new
    @running_threads = []

  end

  def run(&block)
    @pool.pop
    @mutex.synchronize do
      @running_threads << Thread.start do

        begin
          block[]

        rescue Exception => e
          puts "Exception: #{e.message}\n#{e.backtrace}"

        ensure
          @pool << 1

        end
      end
    end
  end

  def await_completion
    @running_threads.each &:join

  end
end

#####################################################################################
#

class Scan

  def initialize(input, type, fuzzer)
    # Setup instance variables
    # Original code allows for subnets to be included in @input, but as this wasn't implemented into inqServices @inputAlt removes the trailing subnet.
    # As both Nikto and Wfuzz need the protocol and/or port, I will need to use @input, but I need to sub out the "bad" chars for output names

    # Possible inputs + output (For use by Nikto/Wfuzz)
    #  http://127.0.0.1         ->  127.0.0.1
    #  127.0.0.1:8080           ->  127.0.0.1:8080
    #  https://127.0.0.1:8443   ->  https://127.0.0.1:8443

    @input = input

    # Possible inputs + output (For use by dir structure)
    #  http://127.0.0.1         ->  http-127.0.0.1
    #  127.0.0.1:8080           ->  127.0.0.1-8080
    #  https://127.0.0.1:8443   ->  https-127.0.0.1-8443

    # Set the output to just have the value without modification.  If it already confirms, it won't be altered.
    @inputAlt = input

    if @inputAlt.include? '://'
      @inputAlt = @inputAlt.sub '://', '-'
    end

    if @inputAlt.include? ':'
      @inputAlt = @inputAlt.sub ':', '-'
    end

    while @inputAlt.include? '/' do
      @inputAlt = @inputAlt.sub '/', '-'
    end

    # Prefix the name of the script
    @inputAlt = "inqHTTP_#{@inputAlt}"

    # Configure directory structure for creating the dir
    @baseDir = "#{$directory}/#{@inputAlt}"

    # Configure boolean for scan logic
    if type == "nikto"
      @nikto = true
      @fuzz = false
    elsif type == "fuzz"
      @nikto = false
      @fuzz = true
    else
      @nikto = true
      @fuzz = true
    end

    # Configure boolean for scan logic
    if fuzzer == "wfuzz"
      @wfuzz = true
      @gobuster = false
    elsif fuzzer == "gobuster"
      @wfuzz = false
      @gobuster = true
    else
      @wfuzz = true
      @gobuster = true
    end    
    
    # Specifies the wordlists which will be used by wfuzz, in order.
    # TODO: Make this configuration better
    @wfuzzDict = [
      "/usr/share/dirb/wordlists/common.txt", 
      "/usr/share/dirb/wordlists/vulns/tomcat.txt", 
      "/usr/share/wordlists/wildkindcc/RobotsDisallowed/top10000.txt", 
      "/usr/share/wordlists/wildkindcc/WordLists/SecLists/Discovery/Web-Content/nginx.txt",
      "/usr/share/wordlists/wildkindcc/WordLists/SecLists/Discovery/Web-Content/apache.txt", 
      "/usr/share/wordlists/wildkindcc/WordLists/SecLists/Discovery/Web-Content/ApacheTomcat.fuzz.txt", 
      "/usr/share/wordlists/wildkindcc/WordLists/SecLists/Discovery/Web-Content/CMS/sharepoint.txt", 
      "/usr/share/wordlists/wildkindcc/WordLists/SecLists/Discovery/Web-Content/iis.txt", 
      "/usr/share/wordlists/wildkindcc/WordLists/SecLists/Discovery/Web-Content/CMS/sharepoint.txt", 
      #"/usr/share/wordlists/dirbuster/directory-list-2.3-medium.txt", 
      "/usr/share/wordlists/wildkindcc/WordLists/SecLists/Discovery/Web-Content/big.txt"
    ]
    @scanLocation = Hash.new

    if File.exists?(@baseDir)
      confirm = ask("[Warning]: Directory [#{@baseDir}] exists!\n".error + "Do you want to continue [Y] or exit [N]?".error) { |yn| yn.limit = 1, yn.validate = /[yn]/i }
      exit unless confirm.downcase == 'y'
    else
      puts "Creating #{@baseDir}".notification
      Dir.mkdir(@baseDir)
    end
    
  end

  def nikto()
    if @nikto
      # Prepare to jump out to bash execution
      outputFile = "#{@baseDir}/nikto_#{@inputAlt}.txt"
      puts ""
      puts "Commencing Nikto against [#{@input}]".event
      puts ""
      output = File.open("#{outputFile}", "w+")
      output.close

      cmd = "nikto -host #{@input}"
      `#{cmd} | tee -a #{outputFile}`
      puts ""
      puts "Nikto scan against [#{@input}] complete! See [#{outputFile}]".success        
      puts ""
    end 
  end

  def wfuzz()
    if @fuzz && @wfuzz
      # Prepare to jump out to bash execution
      outputFile = "#{@baseDir}/wfuzz_#{@inputAlt}.txt"
      puts "The following Wfuzz dictionaries will be executed in order:".event
      dictCount = 0
      @wfuzzDict.each_with_index do |dict,count|     
        puts "[#{'%02d' % (count + 1)}] #{dict}".notification
        dictCount += 1
      end
      puts ""
      puts "Commencing Wfuzz against [#{@input}]".event
      puts ""
      # This will overwrite a files of the same name if it exists.
      output = File.open("#{outputFile}", "w+")
      output.close
      options = ["-R 2", "--sc 200,204,301,302,307,403"]
      options = options.join(" ")  

      # Execute Wfuzz for all configured wordlists
      @wfuzzDict.each_with_index do |dict,count|
        cmd = "wfuzz -v -c -w #{dict} #{options} #{@input}/FUZZ"
        `echo #{cmd.debug} >> #{outputFile}`
        `#{cmd} | tee -a #{outputFile}`
        puts "Complete [#{'%02d' % (count + 1)}/#{'%02d' % dictCount}]: #{dict}".event
      end
          
      puts ""
      puts "Wfuzz against [#{@input}] complete! See [#{outputFile}]".success  
      puts ""
    end
  end

  def gobuster()
    if @fuzz && @gobuster
      # Prepare to jump out to bash execution
      outputFile = "#{@baseDir}/gobuster_#{@inputAlt}.txt"
      puts "The following Gobuster dictionaries will be executed in order:".event
      dictCount = 0
      @wfuzzDict.each_with_index do |dict,count|     
        puts "[#{'%02d' % (count + 1)}] #{dict}".notification
        dictCount += 1
      end
      puts ""
      puts "Commencing Gobuster against [#{@input}]".event
      puts ""
      # This will overwrite a files of the same name if it exists.
      output = File.open("#{outputFile}", "w+")
      output.close
      options = ["-s 200,204,301,302,307,403"]
      options = options.join(" ")  

      # Execute Gobuster for all configured wordlists
      @wfuzzDict.each_with_index do |dict,count|       
        cmd = "gobuster -u #{@input} -k -l #{options} -w \"#{dict}\""
        puts cmd.debug
        `echo #{cmd.debug} >> #{outputFile}`
        `#{cmd} | tee -a #{outputFile}`
        puts "Complete [#{'%02d' % (count + 1)}/#{'%02d' % dictCount}]: #{dict}".event
      end
          
      puts ""
      puts "Gobuster against [#{@input}] complete! See [#{outputFile}]".success  
      puts ""
    end
  end

  # For lack of a better way, use these functions to return the base filename and location of each scan file
#  def initialTCP_location
#    @scanLocation[@scanType[0]]
#  end

end

def scan(input)
  # Performs a scan for a single host or subnet, depending what is passed via input.
  

  puts "#######################################################".event	
  puts "Commencing scan against [#{input}]".event
  puts ""

  scan = Scan.new(input, $options[:type], $options[:fuzzer])
  threads = []
  
  # General Thread Execution
  threads << Thread.new {scan.nikto}
  threads << Thread.new {scan.wfuzz}
  threads << Thread.new {scan.gobuster}
  ThreadsWait.all_waits(*threads)
 
  # Trivial to add this infomration for <input> into a database for reference later.
  #puts scan.initialTCP_location.debug
  #puts scan.initialUDP_location.debug
  #puts scan.allPortsTCP_location.debug
  #puts scan.initialTCP_C_location.debug
  #puts scan.allPortsTCP_C_location.debug

  puts "Scans completed for [#{input}]".success
  puts ""

end

#####################################################################################
# Main program Start

begin
  pool = ThreadPool.new $threads

  $input.each do |host|
    pool.run{
      scan(host)
    }     

  end

  pool.await_completion

rescue SystemExit, Interrupt
	puts "[Ctrl + C] caught! Exiting".error
	abort()
end
