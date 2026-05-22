//! Integration tests for the TAME cipher.

use cryptobscura::tame::Tame;

cipher::block_cipher_test!(tame_kat_128, "tame_128", Tame);
cipher::block_cipher_test!(tame_kat_192, "tame_192", Tame);
cipher::block_cipher_test!(tame_kat_256, "tame_256", Tame);
cipher::block_cipher_test!(tame_kat_320, "tame_320", Tame);
cipher::block_cipher_test!(tame_kat_384, "tame_384", Tame);
cipher::block_cipher_test!(tame_kat_448, "tame_448", Tame);
cipher::block_cipher_test!(tame_kat_512, "tame_512", Tame);
