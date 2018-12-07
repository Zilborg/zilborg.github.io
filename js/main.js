var add_to_end = "/E:X/RL:X/RC:X/CR:X/IR:X/AR:X/MAV:X/MAC:X/MPR:X/MUI:X/MS:X/MC:X/MI:X/MA:X";
var result_cvss_calc;
var result_bis_imp_calc;
$(window).on('load', function() {
    $('input:radio[id="AV:N"]').prop('checked', true);
    $('input:radio[id="AC:L"]').prop('checked', true);
    $('input:radio[id="PR:N"]').prop('checked', true);
    $('input:radio[id="UI:N"]').prop('checked', true);
    $('input:radio[id="S:U"]').prop('checked', true);
    $('input:radio[id="C:N"]').prop('checked', true);
    $('input:radio[id="I:N"]').prop('checked', true);
    $('input:radio[id="A:N"]').prop('checked', true);
    $('input:radio[id="FD:L"]').prop('checked', true);
    $('input:radio[id="RD:M"]').prop('checked', true);
    $('input:radio[id="NC:M"]').prop('checked', true); 
    $('input:radio[id="PV:O"]').prop('checked', true);
    own_calc_cvss();
    own_calc_bis_imp();
    own_calc_fin();  
    own_collect_all_results();
});
    var result;
$(document).ready(function() {
    $('input:radio[name=AV]').change(function() {
        $( "p[id=cvss_AV]" ).text( $(this).attr('id') );
        own_calc_cvss();
        own_calc_fin();
        own_collect_all_results();
    });
    $('input:radio[name=AC]').change(function() {
        $( "p[id=cvss_AC]" ).text( $(this).attr('id') );
        own_calc_cvss();
        own_calc_fin();
        own_collect_all_results();
    });
    $('input:radio[name=PR]').change(function() {
        $( "p[id=cvss_PR]" ).text( $(this).attr('id') );
        own_calc_cvss();
        own_calc_fin();
        own_collect_all_results();
    });
    $('input:radio[name=UI]').change(function() {
        $( "p[id=cvss_UI]" ).text( $(this).attr('id') );
        own_calc_cvss();
        own_calc_fin();
        own_collect_all_results();
    });
    $('input:radio[name=S]').change(function() {
        $( "p[id=cvss_S]" ).text( $(this).attr('id') );
        own_calc_cvss();
        own_calc_fin();
        own_collect_all_results();
    });
    $('input:radio[name=C]').change(function() {
        $( "p[id=cvss_C]" ).text( $(this).attr('id') );
        own_calc_cvss();
        own_calc_fin();
        own_collect_all_results();
    });
    $('input:radio[name=I]').change(function() {
        $( "p[id=cvss_I]" ).text( $(this).attr('id') );
        own_calc_cvss();
        own_calc_fin();
        own_collect_all_results();
    });
    $('input:radio[name=A]').change(function() {
        $( "p[id=cvss_A]" ).text( $(this).attr('id') );
        own_calc_cvss();
        own_calc_fin();
        own_collect_all_results();
    });
    $('input:radio[name=RD]').change(function() {
        $( "p[id=bis_RD]" ).text( $(this).attr('id') );
        own_calc_bis_imp();
        own_calc_fin();
        own_collect_all_results();
    });
    $('input:radio[name=FD]').change(function() {
        $( "p[id=bis_FD]" ).text( $(this).attr('id') );
        own_calc_bis_imp();
        own_calc_fin();
        own_collect_all_results();
    });
    $('input:radio[name=NC]').change(function() {
        $( "p[id=bis_NC]" ).text( $(this).attr('id') );
        own_calc_bis_imp();
        own_calc_fin();
        own_collect_all_results();
    });
    $('input:radio[name=PV]').change(function() {
        $( "p[id=bis_PV]" ).text( $(this).attr('id') );
        own_calc_bis_imp();
        own_calc_fin();
        own_collect_all_results();
    });

});




own_calc_cvss = function (){
    result_cvss_calc = CVSS.calculateCVSSFromVector($.trim($( "div[id=Result_cvss]").text()) + add_to_end);
    $( "div[id=level_vuln_cvss]").text(result_cvss_calc.baseSeverity);
    $( "span[id=score_cvss]").text(result_cvss_calc.baseMetricScore);
};
own_calc_bis_imp = function (){
    result_bis_imp_calc = BIS_IMP.calculateBisImpFromVector($.trim($( "div[id=Result_bis_imp]").text()));
//    console.log(result_bis_imp_calc)
    $( "div[id=level_vuln_bis_imp]").text(result_bis_imp_calc.level);
    $( "span[id=score_bis_imp]").text(result_bis_imp_calc.score);
}
own_calc_fin = function (){
    fin_res_score = (parseFloat(result_cvss_calc.baseMetricScore) + parseFloat(result_bis_imp_calc.score))/2;
    $( "span[id=fin_level]").text(evalute_level_fin(fin_res_score));
//    console.log(result_cvss_calc)
    $( "span[id=fin_score]").text(fin_res_score);
//    console.log(fin_res_score)
}
own_collect_all_results =function() {
    $('textarea#all_fin_results').val("** " + $("span[id=fin_level]").text() + " = " + $.trim($( "span[id=fin_score]").text()) + "\n** " + $.trim($( "div[id=Result_cvss]").text()) + " = " + $.trim($("span[id=score_cvss]").text() + "\n** " + $.trim($( "div[id=Result_bis_imp]").text()) + " = " + $.trim($( "span[id=score_bis_imp]").text())))
}

evalute_level_fin =function(score){
    if (score >= 0 &&  score < 3.0) {
        return "Informative";
    };
    if (score >= 3 &&  score < 4.5) {
        return "Low";
    };
    if (score >= 4.5 &&  score < 7.0) {
        return "Medium";
    }; 
    if (score >= 7.0 &&  score < 9.0) {
        return "High";
    };
    if (score >= 9.0 &&  score <= 10) {
        return "Critical";
    }; 
};
function copyToClipboard_cvss() {
    var $temp = $("<input>");
    $("body").append($temp);
    $temp.val($.trim($( "div[id=Result_cvss]").text()) + " = " + $.trim($("span[id=score_cvss]").text())).select();
    document.execCommand("copy");
    $temp.remove();
}
function copyToClipboard_bis_imp() {
    var $temp = $("<input>");
    $("body").append($temp);
    $temp.val($.trim($( "div[id=Result_bis_imp]").text()) + " = " + $.trim($( "span[id=score_bis_imp]").text())).select();
    document.execCommand("copy");
    $temp.remove();
}
function copyToClipboard_fin_res() {
    var $temp = $("<input>");
    $("body").append($temp);
    $temp.val($.trim($( "span[id=fin_level]").text()) + " = " + $.trim($( "span[id=fin_score]").text())).select();
    document.execCommand("copy");
    $temp.remove();
}
function copyToClipboard_collected_res() {
  console.log($('textarea#all_fin_results').val())
    $('textarea#all_fin_results').select();
    document.execCommand("copy");
}

