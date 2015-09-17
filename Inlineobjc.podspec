Pod::Spec.new do |s|

# Common settings
  s.name         = "Inlineobjc"
  s.version      = "0.1.13"
  s.summary      = "Inline Objective-C small functions for more stable and safer code"
  s.description  = <<-DESC
Inline Objective-C small functions for more stable and safer code. Few usefull daily functions.
                      DESC
  s.homepage     = "https://github.com/OlehKulykov/Inlineobjc"
  s.license      = { :type => 'MIT', :file => 'LICENSE' }
  s.author       = { "Oleh Kulykov" => "info@resident.name" }
  s.source       = { :git => 'https://github.com/OlehKulykov/Inlineobjc.git', :tag => s.version.to_s, :submodules => "true" }

# Platforms
  s.platform     = :ios, '7.0'

# Build  
  s.source_files = '*.h'
  s.public_header_files = '*.h'
  s.requires_arc = true
  s.libraries    = 'z'
  s.framework = 'CoreFoundation', 'CoreGraphics'
end
