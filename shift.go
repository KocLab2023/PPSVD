package main

import (
	"github.com/tuneinsight/lattigo/v6/core/rlwe"
	"github.com/tuneinsight/lattigo/v6/schemes/ckks"
	"math"
)

// 求两个向量的外积outer(vecLeft, vecRight)
func HomomoOuterProduct(ptVector *rlwe.Plaintext, ctVec *rlwe.Ciphertext,
	eval *ckks.Evaluator, n int, evalInnsum *ckks.Evaluator, batch int,
	params ckks.Parameters, kgen *rlwe.KeyGenerator, rlk *rlwe.RelinearizationKey, sk *rlwe.SecretKey,
	ctVec0 *rlwe.Ciphertext, ctVec00 *rlwe.Ciphertext, ecd *ckks.Encoder) (ctVecOuter *rlwe.Ciphertext) {
	var err error

	mask_vecs := make([][]float64, n)
	for i := 0; i < n; i++ {
		mask_vecs[i] = make([]float64, n) // 每个向量的长度为 n
	}

	// 按规则修改向量
	for i := 0; i < n; i++ {
		mask_vecs[i][i] = 1.0 // 设置第 i 个向量的第 i 个元素为 1
	}
	for i, vector := range mask_vecs {
		if err = ecd.Encode(vector, ptVector); err != nil {
			panic(err)
		}
		tempVec, err := eval.MulRelinNew(ctVec, ptVector)
		if err != nil {
			panic(err)
		}

		// 向右旋转(n - 1) * (i + 1)位
		rotLeft := -(n - 1) * (i + 1)
		galElsRotLeft := []uint64{
			params.GaloisElement(rotLeft)}
		rotEvalLeft := eval.WithKey(rlwe.NewMemEvaluationKeySet(rlk, kgen.GenGaloisKeysNew(galElsRotLeft, sk)...))

		tempVec, err = rotEvalLeft.RotateNew(tempVec, rotLeft)
		if err != nil {
			panic(err)
		}

		// 对旋转后的向量求内和
		//[1,0,0,0]->[0,0,0,1]->[1,1,1,1]
		if err := evalInnsum.InnerSum(tempVec, batch, n, tempVec); err != nil {
			panic(err)
		}

		ctVec0, err = eval.AddNew(ctVec0, tempVec)
		if err != nil {
			panic(err)
		}
	}
	ctVecLeft := ctVec0

	// 再处理右边的向量

	rotRight := -n
	galElsRotRight := []uint64{
		params.GaloisElement(rotRight)}
	rotEvalRight := eval.WithKey(rlwe.NewMemEvaluationKeySet(rlk, kgen.GenGaloisKeysNew(galElsRotRight, sk)...))

	for i := 0; i < n; i++ {
		ctVec00, err = eval.AddNew(ctVec00, ctVec)
		if err != nil {
			panic(err)
		}
		ctVec, err = rotEvalRight.RotateNew(ctVec, rotRight)
		if err != nil {
			panic(err)
		}
	}
	ctVecRight := ctVec00

	ctVecOuter, err = eval.MulRelinNew(ctVecLeft, ctVecRight)
	if err != nil {
		panic(err)
	}
	if err = eval.Rescale(ctVecOuter, ctVecOuter); err != nil {
		panic(err)
	}

	return ctVecOuter
}

func HomomoEigenShift(ctRowVec *rlwe.Ciphertext, ctEigenVec *rlwe.Ciphertext, ctEigenVal *rlwe.Ciphertext,
	rotEval *ckks.Evaluator, rot int, ptVector *rlwe.Plaintext, eval *ckks.Evaluator, n int,
	evalInnsum *ckks.Evaluator, batch int, params ckks.Parameters, kgen *rlwe.KeyGenerator,
	rlk *rlwe.RelinearizationKey, sk *rlwe.SecretKey, ctVec0 *rlwe.Ciphertext,
	ctVec00 *rlwe.Ciphertext, ctVec000 *rlwe.Ciphertext, ecd *ckks.Encoder) (ctShiftMat *rlwe.Ciphertext) {

	var err error
	ctVecOuter := HomomoOuterProduct(ptVector, ctEigenVec, eval, n, evalInnsum, batch, params, kgen, rlk, sk, ctVec0, ctVec00, ecd)

	// 计算ctVecOuter中的每个值与ctEigenVal的乘积
	// multi & add & rotate
	nPow := math.Pow(float64(n), 2)
	for i := 0; i < int(nPow); i++ {
		tempVec, err := eval.MulRelinNew(ctEigenVal, ctVecOuter)
		if err != nil {
			panic(err)
		}
		if err = eval.Rescale(tempVec, tempVec); err != nil {
			panic(err)
		}

		ctVec000, err = eval.AddNew(ctVec000, tempVec)
		if err != nil {
			panic(err)
		}

		ctEigenVal, err = rotEval.RotateNew(ctEigenVal, rot)
		if err != nil {
			panic(err)
		}
	}
	ctEigenValMulOuterVec := ctVec000

	ctShiftMat, err = eval.SubNew(ctRowVec, ctEigenValMulOuterVec)
	if err != nil {
		panic(err)
	}

	return ctShiftMat
}
