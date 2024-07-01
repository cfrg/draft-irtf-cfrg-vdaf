from typing import Any, TypeVar

from common import gen_rand
from vdaf import Vdaf, run_vdaf

Measurement = TypeVar("Measurement")
AggParam = TypeVar("AggParam")
PublicShare = TypeVar("PublicShare")
InputShare = TypeVar("InputShare")
AggShare = TypeVar("AggShare")
AggResult = TypeVar("AggResult")
PrepState = TypeVar("PrepState")
PrepShare = TypeVar("PrepShare")
PrepMessage = TypeVar("PrepMessage")


def test_vdaf(
        vdaf: Vdaf[
            Measurement,
            AggParam,
            PublicShare,
            InputShare,
            list[Any],  # OutShare
            AggShare,
            AggResult,
            PrepState,
            PrepShare,
            PrepMessage,
        ],
        agg_param: AggParam,
        measurements: list[Measurement],
        expected_agg_result: AggResult,
        print_test_vec: bool = False,
        test_vec_instance: int = 0) -> None:
    # Test that the algorithm identifier is in the correct range.
    assert 0 <= vdaf.ID and vdaf.ID < 2 ** 32

    # Run the VDAF on the set of measurmenets.
    nonces = [gen_rand(vdaf.NONCE_SIZE) for _ in range(len(measurements))]
    verify_key = gen_rand(vdaf.VERIFY_KEY_SIZE)
    agg_result = run_vdaf(vdaf,
                          verify_key,
                          agg_param,
                          nonces,
                          measurements,
                          print_test_vec,
                          test_vec_instance)
    if agg_result != expected_agg_result:
        print('vdaf test failed ({} on {}): unexpected result: got {}; want {}'
              .format(vdaf.test_vec_name, measurements, agg_result,
                      expected_agg_result))
