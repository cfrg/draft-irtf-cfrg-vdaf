from common import gen_rand
from vdaf import run_vdaf


def test_vdaf(Vdaf,
              agg_param,
              measurements,
              expected_agg_result,
              print_test_vec=False,
              test_vec_instance=0):
    # Test that the algorithm identifier is in the correct range.
    assert 0 <= Vdaf.ID and Vdaf.ID < 2 ** 32

    # Run the VDAF on the set of measurmenets.
    nonces = [gen_rand(Vdaf.NONCE_SIZE) for _ in range(len(measurements))]
    verify_key = gen_rand(Vdaf.VERIFY_KEY_SIZE)
    agg_result = run_vdaf(Vdaf,
                          verify_key,
                          agg_param,
                          nonces,
                          measurements,
                          print_test_vec,
                          test_vec_instance)
    if agg_result != expected_agg_result:
        print('vdaf test failed ({} on {}): unexpected result: got {}; want {}'
              .format(Vdaf.test_vec_name, measurements, agg_result,
                      expected_agg_result))
