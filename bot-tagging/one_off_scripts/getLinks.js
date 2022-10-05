var arr = [];
var domain = "http://red171.com";
for (var i = 0; i < document.links.length; i++) {
    console.log(document.links[i].href);
    let href = "";
    let domainIdx = document.links[i].href.indexOf(domain);
    if (domainIdx > -1) {
        href = document.links[i].href;
        href = href.substring(domainIdx + domain.length);
    }
    if (href.length > 0) {
        arr.push('"' + href + '",');
    }
}
arr = new Set(arr);
arr = new Array(...arr);
arr.sort();
arr.join("\n");