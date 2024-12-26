#include <iostream>
using namespace std;

main()
{
    int num;
    cout << "Number of values: ";
    cin >> num;

    float arr[num];
    float resistance = 0;

    for(int idx = 0; idx < num; idx++)
    {
        cout << "Enter element: ";
        cin >> arr[idx];
        resistance = resistance + arr[idx];
    }
    cout << "Resistance: " << resistance << " ohms.";
}