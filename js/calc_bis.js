var BIS_IMP = {
};
BIS_IMP.Weight = {
  FD: {
    L: 1,
    M: 3,
    S: 7,
    B: 10
  },
  RD: {
    M: 1,
    LM: 4,
    LG: 5,
    B: 10
  },
  NC: {
    M: 2,
    C: 6,
    H: 10
  },
  PV: {
    O: 3,
    H: 5,
    T: 7,
    M: 10
  },
};
BIS_IMP.calculateBisImpFromValues = function (FD, RD, NC, PV){
  var metricWeightFD = BIS_IMP.Weight.FD[FD];
  var metricWeightRD = BIS_IMP.Weight.RD[RD];
  var metricWeightNC = BIS_IMP.Weight.NC[NC];
  var metricWeightPV = BIS_IMP.Weight.PV[PV];
  BIS_IMP.result = (metricWeightFD + metricWeightRD + metricWeightNC + metricWeightPV)/4
  if (BIS_IMP.result >= 0 &&  BIS_IMP.result <= 5) {
    BIS_IMP.level = "Low";
  };
  if (BIS_IMP.result >= 4 &&  BIS_IMP.result <= 6) {
    BIS_IMP.level = "Medium";
  };
   if (BIS_IMP.result >= 7 &&  BIS_IMP.result <= 10) {
    BIS_IMP.level = "High";
  }; 
  return {
  	score: BIS_IMP.result,
  	level: BIS_IMP.level
  }
}

BIS_IMP.calculateBisImpFromVector = function (vectorString){
	vectorString = vectorString.slice(12)
	//console.log(vectorString)
	var metricValues = {
	    FD: undefined,
	    RD: undefined,
	    NC: undefined,
	    PV: undefined
	}
	var metricNameValue = vectorString.split('/');
	for (var i in metricNameValue) {
	    if (metricNameValue.hasOwnProperty(i)) {
	      var singleMetric = metricNameValue[i].split(':');
	      metricValues[singleMetric[0]] = singleMetric[1]
	    }
    }
    return BIS_IMP.calculateBisImpFromValues(metricValues.FD, metricValues.RD, metricValues.NC, metricValues.PV)
};