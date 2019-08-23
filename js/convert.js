function convert_to_md() {

  var CSP = $('textarea#raw_CSP').val().trim();


  if (/^[Cc]ontent-security-policy-report-only:[\s]*/g.test(CSP)) {
    HEAD = '### Content Security Policy (read only)\n|Direcrive| Value|\n|--|--';
    CSP = CSP.replace(/^[Cc]ontent-security-policy-report-only:[\s]*/g, ";");
  } else if (/^[Cc]ontent-security-policy:[\s]*/g.test(CSP)) {
    HEAD = '### Content Security Policy\n|Direcrive| Value|\n|--|--';
    CSP = CSP.replace(/^[Cc]ontent-security-policy:[\s]*/g, ";");
  } else {
    HEAD = '|Direcrive| Value|\n|--|--'
    CSP = ';' + CSP
  };


  var Direcrives = ['base-uri', 'block-all-mixed-content', 'child-src', 'connect-src', 'default-src',
                    'disown-opener', 'font-src', 'form-action', 'frame-ancestors', 'frame-src',
                    'img-src', 'manifest-src', 'media-src', 'navigate-to', 'object-src', 'plugin-types',
                    'prefetch-src', 'referrer', 'report-to', 'report-uri', 'require-sri-for', 'sandbox',
                    'script-src', 'script-src-attr', 'script-src-elem', 'style-src', 'style-src-attr',
                    'style-src-elem', 'trusted-types', 'upgrade-insecure-requests', 'worker-src'];


  for (var i = 0; i < Direcrives.length; i++) {
    CSP= CSP.replace(new RegExp("[\n ]*;[\n ]*" + Direcrives[i] + "[\s]?", "m"), "|\n|**" + Direcrives[i] + "**|");
  };
  CSP = CSP + "|"
  CSP = CSP.replace(/\| /g,"|")
  CSP = CSP.replace(/[\s]* /g,"<br>")
  $('pre#out').text(HEAD + CSP);
};
