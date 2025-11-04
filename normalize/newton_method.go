package normalize

import (
	"fmt"
	"github.com/tuneinsight/lattigo/v6/circuits/ckks/bootstrapping"
	"github.com/tuneinsight/lattigo/v6/core/rlwe"
	"github.com/tuneinsight/lattigo/v6/schemes/ckks"
)

func LinearApprox(ctx0 *rlwe.Ciphertext, eval *ckks.Evaluator,
	pta *rlwe.Plaintext, ptb *rlwe.Plaintext) (cty0 *rlwe.Ciphertext) {

	var err error
	cty0, err = eval.MulRelinNew(ctx0, pta)
	if err != nil {
		panic(err)
	}
	cty0, err = eval.AddNew(cty0, ptb)
	if err != nil {
		panic(err)
	}
	return cty0
}

func HomomoNewton(ptf1 *rlwe.Plaintext, ptf2 *rlwe.Plaintext,
	ctVecMulSum *rlwe.Ciphertext, cty0 *rlwe.Ciphertext,
	eval *ckks.Evaluator, btpEval *bootstrapping.Evaluator, d int) (ctyd *rlwe.Ciphertext) {

	fmt.Println()
	fmt.Printf("%4s3.1. Performing homomorphic newton method...", "")
	var err error

	ct3, err := eval.MulRelinNew(ctVecMulSum, ptf1)
	if err != nil {
		panic(err)
	}
	if err = eval.Rescale(ct3, ct3); err != nil {
		panic(err)
	}

	for i := 0; i < d; i++ {
		t, err := eval.MulRelinNew(cty0, ptf2)
		if err != nil {
			panic(err)
		}
		if err = eval.Rescale(t, t); err != nil {
			panic(err)
		}

		y1, err := eval.MulRelinNew(cty0, cty0)
		if err != nil {
			panic(err)
		}
		if err = eval.Rescale(y1, y1); err != nil {
			panic(err)
		}

		y, err := eval.MulRelinNew(cty0, y1)
		if err != nil {
			panic(err)
		}
		if err = eval.Rescale(y, y); err != nil {
			panic(err)
		}

		s, err := eval.MulRelinNew(ct3, y)
		if err != nil {
			panic(err)
		}
		if err = eval.Rescale(s, s); err != nil {
			panic(err)
		}

		cty0, err = eval.SubNew(t, s)

		cty0, err = btpEval.Bootstrap(cty0)
		if err != nil {
			panic(err)
		}

	}
	ctyd = cty0

	//fmt.Printf("Newton method%s", ckks.GetPrecisionStats(params, ecd, dec, want, valyd, 0, false).String())
	return ctyd
}
