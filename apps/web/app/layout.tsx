import type {Metadata} from "next"; import "./globals.css";
export const metadata:Metadata={title:"SAMIIR + FATMA",description:"Secure AI operations platform"};
export default function Layout({children}:{children:React.ReactNode}){return <html lang="en"><body>{children}</body></html>}
