=begin

BETTERCAP

Author : Simone 'evilsocket' Margaritelli
Email  : evilsocket@gmail.com
Blog   : http://www.evilsocket.net/

This project is released under the GPL 3 license.

=end
class RickRoll < BetterCap::Proxy::HTTP::Module
  meta(
    'Name'        => 'RickRoll',
    'Description' => 'Adds a "rickroll" video iframe on every webpage.',
    'Version'     => '1.0.0',
    'Author'      => "Simone 'evilsocket' Margaritelli",
    'License'     => 'GPL3'
  )

  def on_request( request, response )
    # is it a html page?
    if response.content_type =~ /^text\/html.*/
      BetterCap::Logger.info "Inserting video iframe on http://#{request.host}#{request.path}"
      # make sure to use sub! or gsub! to update the instance
      file = File.open(File.dirname(__FILE__) + '/tmp/yplay.txt', "r")
      contents = file.read
      response.body.sub!( '<head>',contents)
    end
  end
end
