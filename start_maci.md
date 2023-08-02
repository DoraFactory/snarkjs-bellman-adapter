# How to start maci
> In this tutorial, we will use this [maci circuit](https://github.com/dorahacksglobal/qf-maci/tree/master/circuits)

## Dwnload some requirements
1. clone this repository with maci
```shell
git clone --recurse-submodules https://github.com/DoraFactory/snarkjs-bellman-adapter.git
```

2. download the ptau file    
You can see all the ptau in [this](https://github.com/iden3/snarkjs#7-prepare-phase-2), we use `powersOfTau28_hez_final_22.ptau`(Also, if your circuit is relatively large in scale, you can choose to use the other ptau file that supports larger circuits). We need to put the ptau file in dir `ptau`.

3. generate proof
```
cd snarkjs-bellman-adapter && ./start_maci_bn128.sh qf-maci
```

You can find the `xxx_hex.json` in dir `circuit/qf-maci/build/final_proof` and `circuit/qf-maci/build/final_verification_key` and you can use the proof data to verify.