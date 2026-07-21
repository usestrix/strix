import hljs from "highlight.js/lib/common";
import http from "highlight.js/lib/languages/http";
import nginx from "highlight.js/lib/languages/nginx";
import apache from "highlight.js/lib/languages/apache";
import dockerfile from "highlight.js/lib/languages/dockerfile";
import properties from "highlight.js/lib/languages/properties";

hljs.registerLanguage("http", http);
hljs.registerLanguage("nginx", nginx);
hljs.registerLanguage("apache", apache);
hljs.registerLanguage("dockerfile", dockerfile);
hljs.registerLanguage("properties", properties);

export default hljs;
