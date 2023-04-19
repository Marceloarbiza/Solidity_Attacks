# Solidity_Attacks

### Reentrancy Attack  

Para comprender mejor el ataque de reentrancia, primero debemos entender el funcionamiento de las funciones y las transacciones en Solidity. Cuando se llama a una función en un contrato inteligente, se inicia una nueva transacción en la red de Ethereum. Durante esta transacción, el contrato inteligente realiza ciertas operaciones y puede llamar a otras funciones o enviar Ether a otros contratos o direcciones. Cuando se llama a una función en un contrato inteligente, cualquier código adicional que se ejecute dentro de esa función se ejecuta en el mismo contexto de la transacción original.

Ahora, para entender mejor cómo funciona un ataque de reentrancia, imaginemos que un contrato inteligente tiene una función que permite a los usuarios retirar Ether de su cuenta en el contrato. Esta función, digamos "withdraw()", realiza una serie de operaciones, como verificar el saldo de la cuenta del usuario, actualizar el saldo y enviar Ether a la dirección del usuario. Ahora, si un atacante malintencionado crea un contrato que llama a la función "withdraw()" del contrato inteligente, pero luego vuelve a llamar a "withdraw()" antes de que la transacción original se haya completado, el contrato malintencionado puede seguir retirando Ether del contrato inteligente de manera repetitiva, aprovechando el hecho de que la función "withdraw()" aún no ha terminado de ejecutarse.

Para ilustrar esto con un ejemplo de código, aquí hay un contrato inteligente de ejemplo llamado "WalletInsegura.sol", que contiene una función "withdraw()" vulnerable al ataque de reentrancia:

WalletInsegura.sol

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
