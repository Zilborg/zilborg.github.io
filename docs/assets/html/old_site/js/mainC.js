var result=0;
$(window).on('load', function() {
    own_calc_cvss();

});
$(document).ready(function() {
    $('input:radio[name=Back]').change(function() {
        own_calc_cvss();
    });
    $('input:radio[name=Front]').change(function() {
        own_calc_cvss();
    });
    $('input:radio[name=Dep]').change(function() {
        own_calc_cvss();
    });
    $('input:radio[name=OutDep]').change(function() {
        own_calc_cvss();
    });
    $('input:radio[name=Ext]').change(function() {
        own_calc_cvss();
    });
    $('input:radio[name=PCI]').change(function() {
        own_calc_cvss();
    });
    $('input:radio[name=GPDR]').change(function() {
        own_calc_cvss();
    });
    $('input:radio[name=SAST]').change(function() {
        own_calc_cvss();
    });
});


own_calc_cvss = function (){

var back =   parseInt( document.querySelector('input[name=Back]:checked').value);
var front =  parseInt( document.querySelector('input[name=Front]:checked').value);
var dep =  parseInt( document.querySelector('input[name=Dep]:checked').value);
var outdep =  parseInt( document.querySelector('input[name=OutDep]:checked').value);
var ext =  parseInt( document.querySelector('input[name=Ext]:checked').value);
var pci =  parseInt( document.querySelector('input[name=PCI]:checked').value);
var gpdr = parseInt(  document.querySelector('input[name=GPDR]:checked').value);
var sast = parseInt(  document.querySelector('input[name=SAST]:checked').value);

if(pci > 0){
    if(ext > 0){
        $( "span[id=ness]").text("PCI Quarterly External Scan");
    }else{
        $( "span[id=ness]").text("Internal PCI Network Scan");
    }
} else {
    if(front > 0){
        $( "span[id=ness]").text("WebApplication Testing");
    } else {
        $( "span[id=ness]").text("Advance Scan");
    }
}

if (dep > 0){
  $( "span[id=dependency]").text("Необходимо провести проверку библиотек!");
}else{
    $( "span[id=dependency]").text("Все ок");
}
  
if(gpdr > 0){
       $( "span[id=logs]").text("Проверьте логи на наличие чувствительных данных!");
}
if(sast > 0){
     $( "span[id=scs]").text("Проведите дополнительный скан");
}
};





