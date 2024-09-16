# nonlinear exponential regression for y = a*exp(b*x)+c
# based on the psuedo-code by JJacquelin
# https://math.stackexchange.com/a/1946510/227162
import numpy as np


def get_coeffs(x, y):
    """
    fit x and y, must have x strictly increasing,
    with y as many (only) numerical entries as x (only numerical entries)
    """
    s = [0]
    for x_k_1, y_k_1, x_k, y_k in zip(x, y, x[1:], y[1:]):
        s.append(s[-1] + (y_k + y_k_1) / (x_k - x_k_1) / 2)
    x_k_x_1__2 = 0
    x_k_x_1_s_k = 0
    y_k_y_1_x_k_x_1 = 0
    s_k__2 = 0
    y_k_y_1_s_k = 0
    for k in range(1, len(x)):
        x_k_x_1__2 += (x[k] - x[0]) * (x[k] - x[0])
        x_k_x_1_s_k += (x[k] - x[0]) * s[k]
        s_k__2 += s[k] * s[k]
        y_k_y_1_x_k_x_1 += (y[k] - y[0]) * (x[k] - x[0])
        y_k_y_1_s_k += (y[k] - y[0]) * s[k]
    m1 = np.matrix([[x_k_x_1__2, x_k_x_1_s_k], [x_k_x_1_s_k, s_k__2]])
    try:
        c = (np.linalg.inv(m1) @ np.array([y_k_y_1_x_k_x_1, y_k_y_1_s_k]))[0,1]
    except np.linalg.LinAlgError:
        return np.average(y), 0, 0
    theta = 0
    theta__2 = 0
    y_sum = 0
    y_theta = 0
    for k in range(len(x)):
        theta_k = np.exp(c * x[k])
        theta += theta_k
        theta__2 += theta_k * theta_k
        y_sum += y[k]
        y_theta += y[k] * theta_k
    m1 = np.matrix([[len(x), theta], [theta, theta__2]])
    try:
        res = np.linalg.inv(m1) @ np.array([y_sum, y_theta])
        a = res[0,0]
        b = res[0,1]
    except np.linalg.LinAlgError:
        return np.average(y), 0, 0
    return a, b, c