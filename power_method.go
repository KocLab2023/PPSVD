package main

import (
	"fmt"
	"github.com/tuneinsight/lattigo/v6/circuits/ckks/bootstrapping"
	"github.com/tuneinsight/lattigo/v6/circuits/ckks/lintrans"
	"github.com/tuneinsight/lattigo/v6/core/rlwe"
	"github.com/tuneinsight/lattigo/v6/schemes/ckks"
	"math"
	"src/eigen/normalize"
)

// 设置Mat * vec相关参数
func LinearTrans(A [][]float64, Slots int, n int, ctVec *rlwe.Ciphertext, params ckks.Parameters,
	ecd *ckks.Encoder, eval *ckks.Evaluator, kgen *rlwe.KeyGenerator, rlk *rlwe.RelinearizationKey,
	sk *rlwe.SecretKey) (lt lintrans.LinearTransformation, ltEval *lintrans.Evaluator) {

	// 创建一个切片存储 n 条对角线
	diagsA := make([][]float64, n)
	for k := 0; k < n; k++ {
		diagsA[k] = make([]float64, n)
	}

	// 提取对角线
	for i := 0; i < n; i++ {
		for k := 0; k < n; k++ {
			diagsA[k][i] = A[i][(i+k)%n]
		}
	}

	//for k := 0; k < n; k++ {
	//	fmt.Printf("第 %d 条对角线: %v\n", k+1, diagsA[k])
	//}

	nonZeroDiagonals := make([]int, n)
	for i := 0; i < n; i++ {
		nonZeroDiagonals[i] = i
	}

	// We allocate the non-zero diagonals and populate them
	diagonals := make(lintrans.Diagonals[float64])

	for _, i := range nonZeroDiagonals {
		tmp := make([]float64, Slots)

		for j := 0; j < n; j++ {
			tmp[j] = diagsA[i][j]
		}

		diagonals[i] = tmp
	}

	ltparams := lintrans.Parameters{
		DiagonalsIndexList:        diagonals.DiagonalsIndexList(),
		LevelQ:                    ctVec.Level(),
		LevelP:                    params.MaxLevelP(),
		Scale:                     rlwe.NewScale(params.Q()[ctVec.Level()]),
		LogDimensions:             ctVec.LogDimensions,
		LogBabyStepGiantStepRatio: 1,
	}
	lt = lintrans.NewTransformation(params, ltparams)
	if err := lintrans.Encode(ecd, diagonals, lt); err != nil {
		panic(err)
	}

	galElsLt := lintrans.GaloisElements(params, ltparams)

	ltEval = lintrans.NewEvaluator(eval.WithKey(rlwe.NewMemEvaluationKeySet(rlk, kgen.GenGaloisKeysNew(galElsLt, sk)...)))
	return lt, ltEval
}

func HomomoMatMutiVec(lt lintrans.LinearTransformation, ltEval *lintrans.Evaluator,
	ctVec *rlwe.Ciphertext, eval *ckks.Evaluator, n int, LogN int, ctVec0 *rlwe.Ciphertext,
	rotEval1 *ckks.Evaluator, rot1 int) (ctLintransVec *rlwe.Ciphertext) {

	var err error

	// 将向量填充到slots中
	// 注意slots长度为logN-1
	logNPow := math.Pow(2, float64(LogN-1))
	// 移动次数要-1
	logNPown := logNPow/float64(n) - 1

	for i := 0; i < int(logNPown); i++ {
		ctVec0, err = eval.AddNew(ctVec, ctVec0)
		if err != nil {
			panic(err)
		}
		ctVec, err = rotEval1.RotateNew(ctVec, rot1)
		if err != nil {
			panic(err)
		}

	}
	ctVec = ctVec0

	if err := ltEval.Evaluate(ctVec, lt, ctVec); err != nil {
		panic(err)
	}

	if err = eval.Rescale(ctVec, ctVec); err != nil {
		panic(err)
	}

	ctLintransVec = ctVec

	return ctLintransVec
}

func HomomoPowerMethod(evalInnsum *ckks.Evaluator, lt lintrans.LinearTransformation,
	ltEval *lintrans.Evaluator, ctVec *rlwe.Ciphertext, eval *ckks.Evaluator, dec *rlwe.Decryptor, ecd *ckks.Encoder, Slots int,
	max_iter int, batch int, n int, ptf1 *rlwe.Plaintext, ptf2 *rlwe.Plaintext,
	pta *rlwe.Plaintext, ptb *rlwe.Plaintext, btpEval *bootstrapping.Evaluator,
	d int, ctVec0 *rlwe.Ciphertext, LogN int, rotEval *ckks.Evaluator, rotEval1 *ckks.Evaluator,
	rot int, rot1 int) (ctLintransVec *rlwe.Ciphertext, ctNormVec *rlwe.Ciphertext, ctEigenVal *rlwe.Ciphertext) {

	var err error
	fmt.Println()
	fmt.Println("3. Performing homomorphic power method...")

	// 计算特征向量
	ctNormVec = ctVec
	//var ctLintransVec *rlwe.Ciphertext
	for i := 0; i < max_iter; i++ {
		fmt.Println()
		fmt.Printf("%2s第%d次迭代...", "", i+1)
		fmt.Println()
		ctLintransVec = HomomoMatMutiVec(lt, ltEval, ctNormVec, eval, n, LogN, ctVec0, rotEval1, rot1)
		LintransVec := dec.DecryptNew(ctLintransVec)
		LintransVecList := make([]float64, Slots)
		if err = ecd.Decode(LintransVec, LintransVecList); err != nil {
			panic(err)
		}

		fmt.Printf("%2sLintransVec: ", "")
		for i := 0; i < 5; i++ {
			fmt.Printf("%20.15f ", LintransVecList[i])
		}
		fmt.Printf("...\n")

		ctVecMulSum := normalize.MulSumVec(evalInnsum, ctLintransVec, ctLintransVec, eval, batch, n)
		cty0 := normalize.LinearApprox(ctVecMulSum, eval, pta, ptb)

		y0 := dec.DecryptNew(cty0)
		y0List := make([]float64, Slots)
		if err = ecd.Decode(y0, y0List); err != nil {
			panic(err)
		}

		fmt.Printf("%2sy0: ", "")
		for i := 0; i < 5; i++ {
			fmt.Printf("%20.15f ", y0List[i])
		}
		fmt.Printf("...\n")

		ctNormVal := normalize.HomomoNewton(ptf1, ptf2, ctVecMulSum, cty0, eval, btpEval, d)

		NormVal := dec.DecryptNew(ctNormVal)
		NormValList := make([]float64, Slots)
		if err = ecd.Decode(NormVal, NormValList); err != nil {
			panic(err)
		}

		fmt.Println()
		fmt.Printf("%2sNormVal: ", "")
		for i := 0; i < 5; i++ {
			fmt.Printf("%20.15f ", NormValList[i])
		}
		fmt.Printf("...\n")

		ctNormVec = normalize.NormVect(ctNormVal, ctLintransVec, ctVec0, rotEval, eval, n, rot)
	}

	// 计算特征值
	ctLintransNormVec := normalize.MulSumVec(evalInnsum, ctLintransVec, ctNormVec, eval, batch, n)

	ctNormVec2 := normalize.MulSumVec(evalInnsum, ctNormVec, ctNormVec, eval, batch, n)

	ctNormVec4, err := eval.MulRelinNew(ctNormVec2, ctNormVec2)
	if err != nil {
		panic(err)
	}
	if err = eval.Rescale(ctNormVec4, ctNormVec4); err != nil {
		panic(err)
	}

	cty01 := normalize.LinearApprox(ctNormVec4, eval, pta, ptb)

	ctNormVecVal := normalize.HomomoNewton(ptf1, ptf2, ctNormVec4, cty01, eval, btpEval, d)

	ctEigenVal, err = eval.MulRelinNew(ctLintransNormVec, ctNormVecVal)
	if err != nil {
		panic(err)
	}
	if err = eval.Rescale(ctEigenVal, ctEigenVal); err != nil {
		panic(err)
	}

	fmt.Println()

	return ctLintransVec, ctNormVec, ctEigenVal
}
