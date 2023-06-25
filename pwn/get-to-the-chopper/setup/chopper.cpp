#include <cstdlib>
#include <cstring>
#include <exception>
#include <iostream>
#include <limits>
#include <numeric>
#include <sstream>
#include <vector>

#define KG_PER_LB (0.453592)

void get_float(float &var)
{

    std::cin >> var;

    if (std::cin.fail()) {
      std::cin.clear();
    }
    std::cin.ignore(std::numeric_limits<std::streamsize>::max(), '\n');
}

void get_int(int &var)
{

    std::cin >> var;

    if (std::cin.fail()) {
      std::cin.clear();
    }
    std::cin.ignore(std::numeric_limits<std::streamsize>::max(), '\n');
}

inline bool ends_with(std::string const & value, std::string const & ending)
{
    if (ending.size() > value.size()) return false;
    return std::equal(ending.rbegin(), ending.rend(), value.rbegin());
}

class CHOPper {
    private:
        size_t engineModelIndex;
        uint64_t weight;
        float bladeLength;
        int masterPassword;

        const static std::vector<std::string> engineModels;
        static float bladeLenRatio;

        void customizeWeight(void);
        void customizeEngine(void);
        void customizeBladeLength(void);
        std::string getEngineModel(void);

    public:
        CHOPper();
        void customize(void);
        void fly(void);
};

const std::vector<std::string> CHOPper::engineModels =
{"PlasmaDrive 5000", "IonicPropel Vortex", "AeroDynamo X3"};

float CHOPper::bladeLenRatio = 0.1;

CHOPper::CHOPper()
{
    this->masterPassword = 0x1337cafe;
    this->weight = 0x1000;
    this->bladeLength = this->weight * CHOPper::bladeLenRatio;

    std::cout << "Chopper created!" << std::endl;
}

std::string CHOPper::getEngineModel(void) {

    return CHOPper::engineModels.at(this->engineModelIndex);
}

void CHOPper::customizeEngine(void) {
    int engineChoice;

    std::cout << "=== Engine Model Selection ===" << std::endl;
    for (int i = 0; i < engineModels.size(); ++i) {
        std::cout << i + 1 << ". " << engineModels.at(i) << std::endl;
    }
    std::cout << "0. Go back" << std::endl;
    std::cout << "==============================" << std::endl;

    while (1) {
        std::cout << "Enter the index of the engine model you want: ";
        get_int(engineChoice);

        if (engineChoice >= 1 && engineChoice <= engineModels.size()) {
            this->engineModelIndex = engineChoice - 1;
            std::cout << "Engine model set to: " << getEngineModel() << std::endl;
            return;
        } else if (engineChoice == 0) {
            std::cout << "Going back to chopper attribute customization menu." << std::endl;
            return;
        } else {
            std::cout << "Invalid engine model choice. Please try again." << std::endl;
        }
    }
}

void CHOPper::customizeWeight(void) {

    char buffer[0x16];
    int weight;

    std::cout << "Enter the weight of the chopper. " << std::endl;
    std::cout << "Append 'lb' at the end if your input is in pounds, we will automatically convert it to kg: ";

    std::cin.getline(buffer, 0x100);
    if (std::cin.fail()) {
        std::cin.clear();
        std::cin.ignore(std::numeric_limits<std::streamsize>::max(), '\n');
    }

    weight = std::stoi(buffer);

    this->weight = weight;

    if (ends_with(std::string(buffer), std::string("lb"))) {
        this->weight = (float) this->weight * KG_PER_LB;
    }

    std::cout << "Weight set to: " << this->weight << " kg" << std::endl;
}

void CHOPper::customizeBladeLength(void) {

    std::string blade_len_str;
    std::cout << "Choose the blade-len-to-weigth ratio for the CHOPper: ";

    try {
        std::cin >> blade_len_str;
        CHOPper::bladeLenRatio = std::stof(blade_len_str);
        this->bladeLength = this->weight * CHOPper::bladeLenRatio;
    } catch (std::invalid_argument& e) {
        std::cout << "Error when modifying blade length ratio @ " <<
            reinterpret_cast<void *>(&CHOPper::bladeLenRatio) << std::endl;
    }
}

void CHOPper::fly(void)
{
    int master_pass = this->masterPassword;

        std::cout << "Checking up the CHOPper before takeoff..." << std::endl;
        std::cout << "Weight: " << this->weight << "... ok" << std::endl;
        std::cout << "Blade length: " << this->bladeLength << "... ok" << std::endl;
    try {
        std::cout << "Engine: " << getEngineModel() << "... ok" << std::endl;
    } catch (std::out_of_range &e) {

        std::cout << "Uh oh, something went wrong, seems like the CHOPper can't fly!" << std::endl;
        if (master_pass == 0xdeadbeef) {
            std::cout << "Seems like you know the master password! Take control of the chopper." << std::endl;
            std::system("/bin/bash");
        }
    }


    std::cout << "CHOPper is ready for takeoff!" << std::endl;

    exit(0);


}

void CHOPper::customize(void) {
    int choice;

    while (true) {
        std::cout << "=== CHOPper Customization ===" << std::endl;
        std::cout << "1. Engine Model" << std::endl;
        std::cout << "2. Weight" << std::endl;
        std::cout << "3. Blade Length" << std::endl;
        std::cout << "4. Master Password" << std::endl;
        std::cout << "0. Go back" << std::endl;
        std::cout << "======================================" << std::endl;
        std::cout << "Enter your choice: ";

        get_int(choice);

        switch (choice) {
            case 0:
                std::cout << "Exiting CHOPper customization." << std::endl;
                return;
            case 1: {
                        this->customizeEngine();
                        break;
                    }
            case 2:
                    try {
                        this->customizeWeight();
                    } catch (std::exception &e) {
                        std::cout << "Something went wrong when choosing weight!" << std::endl;
                    }
                    break;
            case 3:
                    this->customizeBladeLength();
                    break;
            case 4:
                    std::cout << "Sorry, the master password can only be set by the manufacturer :/" << std::endl;;
            default:
                    std::cout << "No such customization choice. Please try again." << std::endl;
                    break;
        }

        std::cout << std::endl;
    }
}

int main() {
    std::cout << "Welcome to the dystopian future, where AI-controlled choppers dominate the skies!" << std::endl;

    CHOPper *chopper = new CHOPper();

    int choice;
    while (true) {
        std::cout << "=== Welcome to the CHOPper shop! ===" << std::endl;
        std::cout << "1. Customize your chopper" << std::endl;
        std::cout << "2. Fly your chopper" << std::endl;
        std::cout << "====================================" << std::endl;
        std::cout << "Enter your choice: ";
        get_int(choice);
        std::cout << "Choice: " << choice << std::endl;

        switch (choice) {
            case 0:
                std::cout << "Goodbye!" << std::endl;
                return 0;
            case 1:
                chopper->customize();
            case 2:
                chopper->fly();
            default:
                std::cout << "Invalid choice. Please try again." << std::endl;
                break;
        }

        std::cout << std::endl;
    }

    return 0;
}
