int foo(){
    if (1){
        return 1;
    }
    return 0;
}

int bar(){
    for(int i = 0; i < 10; i++){
        if (i == 5){
            return 0;
        }
    }
    return 1;
}

int main(){
    foo();
    bar();
    return 0;
}