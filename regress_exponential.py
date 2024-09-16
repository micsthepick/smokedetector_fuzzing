import numpy as np


def estimate_bc(x, y, a):
    log_y = np.log(y-a)
    b, c = np.polyfit(x, log_y, 1)
    y_pred = np.polyval([b, c], x)
    c = np.exp(c)
    return np.sum((log_y-y_pred)**2), b, c

def get_coeffs(x, y):
    a = 0
    last_a = int(np.floor(min(9, *y) -1))
    last_est, b, c = estimate_bc(x, y, last_a)
    curr_est, b, c = estimate_bc(x, y, a)
    if curr_est > last_est:
        curr_est, last_est = last_est, curr_est
        a, last_a = last_a, a
    while True:
        next_a = (a + last_a) // 2
        if next_a == last_a:
            break
        next_est, b, c = estimate_bc(x, y, next_a)
        if next_est < curr_est:
            curr_est = next_est
            last_a = a
            a = next_a
        else:
            last_a = next_a
    return a, b, c