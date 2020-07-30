# from address import *
# import pytest

# def test_valid_ip_is_valid():
#     """ asserts that exception was thrown AND that message matches """
#     calculator = Calculator()
#     with pytest.raises(CalculatorError) as context:
#         result = calculator.add("two", 3)

#     assert str(context.value) == "type mismatch"

# def test_invalid_ip_raises_error():
#     """ asserts that exception was thrown and that message matches """
#     address = IPv4Address("192.168.1.278")
#     with pytest.raises(CalculatorError) as context:
#         result = calculator.add("two", 3)

#     assert str(context.value) == "type mismatch"


# def test_add_weirder_stuff():
#     calculator = Calculator()
#     with pytest.raises(CalculatorError) as context:
#         result = calculator.add("two", "three")
