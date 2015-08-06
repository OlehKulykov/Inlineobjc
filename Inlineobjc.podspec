Pod::Spec.new do |s|

# Common settings
  s.name         = "Inlineobjc"
  s.version      = "0.1.6"
  s.summary      = "Inline Objective-C small functions"
  s.description  = <<-DESC
Inline Objective-C small functions. Few usefull daily functions.
                      DESC
  s.homepage     = "https://github.com/OlehKulykov/Inlineobjc"
  s.license      = { :type => 'MIT', :file => 'LICENSE' }
  s.author       = { "Oleh Kulykov" => "info@resident.name" }
  s.source       = { :git => 'https://github.com/OlehKulykov/Inlineobjc.git', :tag => s.version.to_s, :submodules => "true" }

# Platforms
  s.platform     = :ios, '7.0'

# Build  
  s.public_header_files = 'UIImage+Inlineobjc.h',
	'UIColor+Inlineobjc.h',
	'NSData+Inlineobjc.h', 
	'NSData+InlineobjcZip.h',
	'NSDictionary+Inlineobjc.h',
	'NSMutableArray+Inlineobjc.h',
	'NSString+Inlineobjc.h'
  s.source_files = 'InlineobjcDummy.m'
  s.requires_arc = true
  s.libraries    = 'z'
  s.framework = 'CoreFoundation', 'CoreGraphics'
end
