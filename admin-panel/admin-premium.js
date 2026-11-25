(function(){
var d=document.documentElement,t;
function pulse(ms){d.classList.add('pa');clearTimeout(t);t=setTimeout(function(){d.classList.remove('pa')},ms||1300)}
window.premiumPulse=pulse;pulse(1600);
addEventListener('click',function(){pulse(1300)},true);
addEventListener('hashchange',function(){pulse(1300)},true);
})();
