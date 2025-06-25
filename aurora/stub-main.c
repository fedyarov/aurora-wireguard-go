

int main(int argc, char const *argv[])
{
    /* rpm-validator in Aurora OS requires main binary with
     * __libc_start_main. Wireguard-go doesn't fit this
     * requirement. */
    return 0;
}
