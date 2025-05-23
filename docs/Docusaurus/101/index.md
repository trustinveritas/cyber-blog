---
title: "The Ultimate Docusaurus Guide"
authors: [asalucci]
tags: [Docusaurus, Guide, "101", trustinveritas, alessandro]
published: 2025-02-24
categories: ["Docusaurus", "Guide", "101"]
---

# The Ultimate Docusaurus Guide: Build Top-Notch Documentation 🔥

## 1. Headings
```markdown
# Heading H1
## Heading H2
### Heading H3
#### Heading H4
##### Heading H5
###### Heading H6
```
# Heading H1
## Heading H2
### Heading H3
#### Heading H4
##### Heading H5
###### Heading H6

---

## 2. Emphasis
```markdown
**bold text**
*italic text*
~~strikethrough~~
`inline code`
```
**bold text**  
*italic text*  
~~strikethrough~~  
`inline code`  

---

## 3. Code Blocks
**Basic code block with syntax highlighting**
````markdown
```js
const greet = () => console.log("Hello World");
```
````
```js
const greet = () => console.log("Hello World");
```

**Including a file name/title**
````markdown
```js title="index.js"
const greet = () => console.log("Hello World");
```
````
```js title="index.js"
const greet = () => console.log("Hello World");
```

**Highlighting specific lines**
````markdown
```jsx {2-3}
function Hello() {
  console.log("Hello World");
  return <h1>Hello!</h1>;
}
```
````
```jsx {2-3}
function Hello() {
  console.log("Hello World");
  return <h1>Hello!</h1>;
}
```

---

## 4. Lists
```markdown
- Item 1
- Item 2
  - Subitem 2.1
  - Subitem 2.2

1. Step one
2. Step two
3. Step three
```
- Item 1
- Item 2
  - Subitem 2.1
  - Subitem 2.2

1. Step one
2. Step two
3. Step three

---

5. Tables
```markdown
| Column 1 | Column 2 | Column 3 |
|----------|----------|----------|
| A        | B        | C        |
| D        | E        | F        |
```

| Column 1 | Column 2 | Column 3 |
|----------|----------|----------|
| A        | B        | C        |
| D        | E        | F        |

---

## 6. Links & Images
```markdown
[Link to Salucci](https://salucci.ch)

![Alt Text for Image](./path-to-image.png)
```

---

## 7. Blockquotes
```markdown
> This is a quote.
>
> And this is the second line of the quote.
```
> This is a quote.
>
> And this is the second line of the quote.

---

## 8. Admonitions
Admonitions are special note boxes. Docusaurus supports several defaults, such as `:::note`, `:::tip`, `:::info`, `:::caution`, and `:::danger`.
```markdown
:::note
**Note:** This is an important note!
:::

:::tip
**Tip:** Here's a helpful tip!
:::

:::info
**Info:** Additional information goes here.
:::

:::caution
**Caution:** Proceed carefully with this step.
:::

:::danger
**Warning:** This can cause serious issues.
:::
```
:::note
**Note:** This is an important note!
:::

:::tip
**Tip:** Here's a helpful tip!
:::

:::info
**Info:** Additional information goes here.
:::

:::caution
**Caution:** Proceed carefully with this step.
:::

:::danger
**Warning:** This can cause serious issues.
:::

---

## 9. Custom Titles in Admonitions
```markdown
:::tip Custom Title
Use a custom title and add your content here.
:::
```
:::tip Custom Title
Use a custom title and add your content here.
:::

---

## 10. Tabs
````markdown
import Tabs from '@theme/Tabs';
import TabItem from '@theme/TabItem';

<Tabs>
  <TabItem value="javascript" label="JavaScript">

```javascript
console.log("Hello JavaScript!");
```

  </TabItem>
  <TabItem value="python" label="Python">

```python
print("Hello Python!")
```

  </TabItem>
</Tabs>
````
import Tabs from '@theme/Tabs';
import TabItem from '@theme/TabItem';

<Tabs>
  <TabItem value="javascript" label="JavaScript">

```javascript
console.log("Hello JavaScript!");
```

  </TabItem>
  <TabItem value="python" label="Python">

```python
print("Hello Python!")
```

  </TabItem>
</Tabs>

---

## 11. Details (Expandable Section)
```markdown
<details>
<summary>Click to expand!</summary>

This content is hidden until you expand it.

</details>
```
<details>
<summary>Click to expand!</summary>

This content is hidden until you expand it.

</details>

---

## 12. Mermaid Diagrams (since Docusaurus v2.0)
````markdown
```mermaid
graph TD
  A[Start] --> B{Decision}
  B -->|Yes| C[Option A]
  B -->|No| D[Option B]

---

## 13. Footnotes


Here is a sentence with a footnote.[^1]

[^1]: This is the content of the footnote.
```
````
```mermaid
graph TD
  A[Start] --> B{Decision}
  B -->|Yes| C[Option A]
  B -->|No| D[Option B]

---

## 13. Footnotes


Here is a sentence with a footnote.[^1]

[^1]: This is the content of the footnote.
```