import aeromiko


def test_initial_values():
    ip = "IP"
    username = "username"
    password = "password"

    my_ap = aeromiko.AP(ip, username, password)

    assert my_ap.ip == ip, f'self.ip should be "{ip}"'
    assert my_ap.username == username, f'self.username should be "{username}"'
    assert my_ap.password == password, f'self.password should be "{password}"'
