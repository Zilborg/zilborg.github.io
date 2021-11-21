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
        $( "p[id=cvss_AV]" ).text( $(this).attr("id") );
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
    check_result_color($( "div[id=level_vuln_cvss]"));
};
own_calc_bis_imp = function (){
    result_bis_imp_calc = BIS_IMP.calculateBisImpFromVector($.trim($( "div[id=Result_bis_imp]").text()));
//    console.log(result_bis_imp_calc)
    $( "div[id=level_vuln_bis_imp]").text(result_bis_imp_calc.level);
    $( "span[id=score_bis_imp]").text(result_bis_imp_calc.score);
    check_result_color($( "div[id=level_vuln_bis_imp]"));
}
own_calc_fin = function (){
    fin_res_score = (parseFloat(result_cvss_calc.baseMetricScore) + parseFloat(result_bis_imp_calc.score))/2;
    if ($( "span[id=should_be_black]").text() == "Result:") {
        $( "span[id=fin_level]").text(evalute_level_fin(fin_res_score, "en"));
    } else if ( $( "span[id=should_be_black]").text() == "Уровень уязвимости:") {
        $( "span[id=fin_level]").text(evalute_level_fin(fin_res_score, "ru"));
    };
    
//    console.log(result_cvss_calc)
    $( "span[id=fin_score]").text(fin_res_score);
//    console.log(fin_res_score)
    check_result_color($( "span[id=fin_level]"));
  
}
own_collect_all_results =function() {
    $('textarea#all_fin_results').val("* " + $("span[id=fin_level]").text() + " = " + $.trim($( "span[id=fin_score]").text()) + "\n* " + $.trim($( "div[id=Result_cvss]").text()) + " = " + $.trim($("span[id=score_cvss]").text() + "\n* " + $.trim($( "div[id=Result_bis_imp]").text()) + " = " + $.trim($( "span[id=score_bis_imp]").text())))
}

evalute_level_fin =function(score, lang){
    if (lang == "en"){
        if (score >= 0 &&  score < 3.0) {
            return "Informative";
        } else if (score >= 3 &&  score < 4.5) {
            return "Low";
        } else if (score >= 4.5 &&  score < 7.0) {
            return "Medium";
        } else if (score >= 7.0 &&  score < 9.0) {
            return "High";
        }else if (score >= 9.0 &&  score <= 10) {
            return "Critical";
        };
    } else if (lang == "ru") {
        if (score >= 0 &&  score < 3.0) {
            return "Информативный";
        } else if (score >= 3 &&  score < 4.5) {
            return "Низкий";
        } else if (score >= 4.5 &&  score < 7.0) {
            return "Средний";
        } else if (score >= 7.0 &&  score < 9.0) {
            return "Высокий";
       } else if (score >= 9.0 &&  score <= 10) {
            return "Критический";
        };
    };
};

function copyToClipboard_collected_res() {
    $('textarea#all_fin_results').select();
    document.execCommand("copy");
}

function check_result_color(_level){
  if (_level.text() == "Informative"){
    _level.parent("div").css("color","#3c91e6")
  } else if (_level.text() == "None"){
    _level.parent("div").css("color","#3c91e6")
  } else if (_level.text() == "Low"){
    _level.parent("div").css("color","#27aa31")
  } else if (_level.text() == "Medium"){
    _level.parent("div").css("color","#e6843c")
  } else if (_level.text() == "High"){
    _level.parent("div").css("color","#e63c3c")
  } else if (_level.text() == "Информативный"){
    _level.parent("div").css("color","#3c91e6")
  } else if (_level.text() == "Не уязвимость"){
    _level.parent("div").css("color","#3c91e6")
  } else if (_level.text() == "Низкий"){
    _level.parent("div").css("color","#27aa31")
  } else if (_level.text() == "Средний"){
    _level.parent("div").css("color","#e6843c")
  } else if (_level.text() == "Высокий"){
    _level.parent("div").css("color","#e63c3c")
  }; 
}

// function input_any_cvss_conf(template){
//   var input_conf_cvss;
//   if (template === undefined){
//     input_conf_cvss = $.trim(prompt("CVSS:3.1"));
//   } else {
//     input_conf_cvss = template;
//   }
//   arr_cvss_conf = input_conf_cvss.split("/");
//   if (arr_cvss_conf.slice(0,1) != "CVSS:3.1") {
//     console.log("Just copy CVSS:3.1 string here.");
//     return
//   };
//   if (arr_cvss_conf.length != "9") {
//     console.log("OK. It start from 'CVSS:3.1'. But it has to 8 parametrs.");
//     return
//   };
//   var bool_check;
//   $.each(arr_cvss_conf.slice(1), function(i, l){
// //    console.log(i + " = " + l);
//     if($('input:radio[id="' + l +'"]').length) {
//       $('input:radio[id="' + l +'"]').prop('checked', true);
//       $( "p[id=cvss_" + l.split(":").slice(0,1) + "]" ).text(l);
//     } else { 
//       alert("Can't find the parameter: " + l);
//     };
//   });
//   own_calc_cvss();
//   own_calc_fin();
//   own_collect_all_results();
// };

// function input_any_bis_imp_conf(template){
//   var input_conf_bis_imp;
//   if (template === undefined){
//     input_conf_bis_imp = $.trim(prompt("BIS-IMP:1.0"));
//   } else {
//     input_conf_bis_imp = template;
//   }
//   arr_bis_imp_conf = input_conf_bis_imp.split("/");
//   if (arr_bis_imp_conf.slice(0,1) != "BIS-IMP:1.0") {
//     console.log("Just copy BIS-IMP:1.0 string here.");
//     return
//   };
//   if (arr_bis_imp_conf.length != "5") {
//     console.log("OK. It start from 'BIS-IMP:1.0'. But it has to 4 parametrs.");
//     return
//   };
//   var bool_check;
//   $.each(arr_bis_imp_conf.slice(1), function(i, l){
// //    console.log(i + " = " + l);
//     if($('input:radio[id="' + l +'"]').length) {
//       $('input:radio[id="' + l +'"]').prop('checked', true);
//       $( "p[id=bis_" + l.split(":").slice(0,1) + "]" ).text(l);
//     } else { 
//       alert("Can't find the parameter: " + l);
//     };
//   });
//   own_calc_bis_imp();
//   own_calc_fin();
//   own_collect_all_results();
// };



