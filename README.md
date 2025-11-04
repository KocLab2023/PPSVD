# Privacy-Preserving Singular Value Decomposition using Fully Homomorphic Encryption
This project implements matrix computations in the encrypted domain using the CKKS homomorphic encryption scheme, including the Power Method and Eigen shift. 
The objective is to perform iterative linear transformations, normalization, and inner/outer product operations on encrypted data, thereby approximating the eigenvalues and eigenvectors of a matrix. 
Through these computations, **privacy-preserving singular value decomposition** is achieved.

> The implementation is based on Lattigo (github.com/tuneinsight/lattigo/v6), which is used to support CKKS-related functionalities including encoding, encryption and decryption, evaluator operations, as well as modules for bootstrapping and linear transformations.


