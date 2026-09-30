#include <iostream>
#include <cstring>
struct Session { char name[16]; };
int main() {
    std::string input;
    std::cin >> input;
    Session *s = new Session();
    std::strcpy(s->name, input.c_str());
    delete s;
    std::cout << s->name;
    std::system(("echo " + input).c_str());
    return 0;
}
