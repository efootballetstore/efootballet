(function(){
var d=document.documentElement,t;
function pulse(ms){d.classList.add('pa');clearTimeout(t);t=setTimeout(function(){d.classList.remove('pa')},ms||1300)}
window.premiumPulse=pulse;pulse(1600);
addEventListener('click',function(){pulse(1300)},true);
addEventListener('hashchange',function(){pulse(1300)},true);
function inField(e){var n=e.target;n=n&&(n.nodeType===1?n:n.parentElement);return !!(n&&n.closest&&n.closest('input,textarea,[contenteditable="true"]'))}
document.addEventListener('contextmenu',function(e){if(!inField(e))e.preventDefault()},true);
document.addEventListener('selectstart',function(e){if(!inField(e))e.preventDefault()},true);
document.addEventListener('dragstart',function(e){e.preventDefault()},true);
})();
