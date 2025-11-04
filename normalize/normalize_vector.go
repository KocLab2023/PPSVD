package normalize

import (
	"fmt"
	"github.com/tuneinsight/lattigo/v6/core/rlwe"
	"github.com/tuneinsight/lattigo/v6/schemes/ckks"
)

func MulSumVec(evalInnsum *ckks.Evaluator, ctVec1 *rlwe.Ciphertext, ctVec2 *rlwe.Ciphertext,
	eval *ckks.Evaluator, batch int, n int) (ctVecMulSum *rlwe.Ciphertext) {

	var err error

	ctVecMulSum, err = eval.MulRelinNew(ctVec1, ctVec2)
	if err != nil {
		panic(err)
	}
	if err = eval.Rescale(ctVecMulSum, ctVecMulSum); err != nil {
		panic(err)
	}

	if err := evalInnsum.InnerSum(ctVecMulSum, batch, n, ctVecMulSum); err != nil {
		panic(err)
	}

	return ctVecMulSum
}

func NormVect(ctNormVal *rlwe.Ciphertext, ctVec *rlwe.Ciphertext,
	ctVec0 *rlwe.Ciphertext, rotEval *ckks.Evaluator,
	eval *ckks.Evaluator, vecLen int, rot int) (ctNormVec *rlwe.Ciphertext) {

	fmt.Println()
	fmt.Printf("%4s3.2. Performing homomorphic normalize vector...", "")

	// Normalize Vector

	// 计算向量中的每个值与NormVal的乘积
	// multi & add & rotate
	for i := 0; i < vecLen; i++ {
		tempVec, err := eval.MulRelinNew(ctVec, ctNormVal)
		if err != nil {
			panic(err)
		}
		if err = eval.Rescale(tempVec, tempVec); err != nil {
			panic(err)
		}

		ctVec0, err = eval.AddNew(ctVec0, tempVec)
		if err != nil {
			panic(err)
		}

		ctNormVal, err = rotEval.RotateNew(ctNormVal, rot)
		if err != nil {
			panic(err)
		}
	}
	ctNormVec = ctVec0

	return ctNormVec
}
