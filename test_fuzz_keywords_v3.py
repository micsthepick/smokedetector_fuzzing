import pytest
import numpy as np
from fuzz_keywords_v3 import get_trend

@pytest.mark.parametrize("x_values, y_values, point, lower_bound, upper_bound", [
    (list(range(1, 5)), [np.exp(i) for i in range(1, 5)], 10, np.exp(10)-20, np.exp(10)+40)
])
def test_get_trend_range(x_values, y_values, point, lower_bound, upper_bound):
    assert np.log(lower_bound) <= get_trend(x_values, y_values, point) <= np.log(upper_bound)

@pytest.mark.parametrize("x_values, y_values, point, lower_bound, upper_bound", [
    (list(range(1, 5)), [5 for i in range(1, 5)], 10, 5 - 0.001, 5 + 0.001)
])
def test_get_trend_range(x_values, y_values, point, lower_bound, upper_bound):
    assert np.log(lower_bound) <= get_trend(x_values, y_values, point) <= np.log(upper_bound)