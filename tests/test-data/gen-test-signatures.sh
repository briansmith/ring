#!/bin/bash

set -ex

test_dir=`dirname $0`
mkdir -p $test_dir
cd $test_dir

messages=( msg1 msg2 )
rsa_key_lengths=( 2048 4096 8192 )
rsa_padding_modes=( pkcs1 pss )
digest_algs=( sha1 sha256 sha384 sha512 )
ec_curves=( prime256v1 secp384r1 )

# get two pieces of random message_id to sign

mkdir -p keys signatures digests messages

for message_file in "${messages[@]}"
do
    dd if=/dev/urandom of="messages/${message_file}.bin" bs=1024 count=1
    for digest_alg in "${digest_algs[@]}"
    do
        openssl dgst -${digest_alg} -binary -out digests/${message_file}_${digest_alg}.bin "messages/${message_file}.bin"
    done
done

# generate rsa keys
for rsa_key_len in "${rsa_key_lengths[@]}"
do
    openssl genrsa -out keys/rsa_${rsa_key_len}.pem ${rsa_key_len}
    openssl rsa -inform pem -in keys/rsa_${rsa_key_len}.pem -outform der -out keys/rsa_${rsa_key_len}.der
    openssl rsa -inform der -in keys/rsa_${rsa_key_len}.der -outform der -pubout \
        -out keys/rsa_${rsa_key_len}_pub_spki.der
    rm -rf keys/*.pem

    for message_file in "${messages[@]}"
    do
        for digest_alg in "${digest_algs[@]}"
        do
            for rsa_padding_mode in "${rsa_padding_modes[@]}"
            do
                if [[ "$rsa_padding_mode" = "pss" ]]; then
                    extra_args="-sigopt rsa_pss_saltlen:-1"
                else
                    extra_args=""
                fi

                openssl dgst "-${digest_alg}" -sign "keys/rsa_${rsa_key_len}.der" \
                    -keyform DER \
                    -sigopt "rsa_padding_mode:${rsa_padding_mode}" \
                    ${extra_args} \
                    -out "signatures/${message_file}_rsa_${rsa_key_len}_${rsa_padding_mode}_${digest_alg}_sig.bin" \
                    "messages/${message_file}.bin"
            done
        done
    done
done

# generate ecdsa keys
for ec_curve in "${ec_curves[@]}"
do
    # confusingly, the -noout here means "output the key, not the curve parameters"
    openssl ecparam -name ${ec_curve} -noout -outform DER -out keys/ecdsa_${ec_curve}.der -genkey
    openssl ec -inform der -in keys/ecdsa_${ec_curve}.der -outform der -pubout \
        -out keys/ecdsa_${ec_curve}_pub_spki.der

    for message_file in "${messages[@]}"
    do
        for digest_alg in "${digest_algs[@]}"
        do
            openssl dgst "-${digest_alg}" -sign "keys/ecdsa_${ec_curve}.der" \
                -keyform DER \
                -out "signatures/${message_file}_ecdsa_${ec_curve}_${digest_alg}_sig.bin" \
                "messages/${message_file}.bin"
        done
    done
done

