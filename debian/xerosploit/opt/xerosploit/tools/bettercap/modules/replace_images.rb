
=begin
BETTERCAP
Author : Simone 'evilsocket' Margaritelli
Email  : evilsocket@gmail.com
Blog   : http://www.evilsocket.net/
This project is released under the GPL 3 license.
=end

# This module requires the --httpd argument being passed
# to bettercap and the --httpd-path pointing to a folder
# which contains a "hack.png" image.
class ReplaceImages < BetterCap::Proxy::HTTP::Module
  meta(
    'Name'        => 'ReplaceImages',
    'Description' => 'Replace all images on web pages.',
    'Version'     => '1.0.0',
    'Author'      => "Simone 'evilsocket' Margaritelli",
    'License'     => 'GPL3'
  )

  def initialize
    opts = BetterCap::Context.get.options.servers
    # make sure the server is running
    raise BetterCap::Error, "The ReplaceImages proxy module needs the HTTPD ( --httpd argument ) running." unless opts.httpd
    # make sure the file we need actually exists
    raise BetterCap::Error, "No ximage.png file found in the HTTPD path ( --httpd-path argument ) '#{opts.httpd_path}'" \
      unless File.exist? "#{opts.httpd_path}/ximage.png"

    @image_url = "\"http://#{BetterCap::Context.get.iface.ip}:#{opts.httpd_port}/ximage.png\""
  end

  def on_request( request, response )
    # is it a html page?
    if response.content_type =~ /^text\/html.*/
      BetterCap::Logger.info "Replacing http://#{request.host}#{request.path} images."

      response.body.gsub! %r/["'][https:\/\/]*[^\s]+\.(png|jpg|jpeg|bmp|gif|webp|svg)["']/i, @image_url
    end
  end
end
